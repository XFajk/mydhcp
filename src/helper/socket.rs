use std::{
    ffi::CString,
    ops::Deref,
    os::{fd::RawFd, raw::c_void},
    rc::Rc,
    time::Duration,
};

use libc::{SO_ATTACH_FILTER, SOL_SOCKET};
use pcap::Capture;

use crate::error::{self, DhcpClientError};

#[derive(Debug)]
pub struct SocketFd(RawFd);

impl SocketFd {
    /// Set a receive timeout on a socket
    pub fn set_socket_timeout(&self, timeout: Duration) -> std::io::Result<()> {
        let tv = libc::timeval {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_usec: (timeout.subsec_micros()) as libc::suseconds_t,
        };

        let ret = unsafe {
            libc::setsockopt(
                self.0,
                SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Remove (clear) the socket timeout by setting it to 0
    pub fn clear_socket_timeout(&self) -> std::io::Result<()> {
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };

        let ret = unsafe {
            libc::setsockopt(
                self.0,
                SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl Deref for SocketFd {
    type Target = RawFd;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<RawFd> for SocketFd {
    type Error = std::io::Error;

    fn try_from(fd: RawFd) -> Result<Self, Self::Error> {
        if fd < 0 {
            Err(std::io::Error::from_raw_os_error(fd))
        } else {
            Ok(SocketFd(fd))
        }
    }
}

impl Drop for SocketFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

#[derive(Debug)]
pub struct RawSocket {
    fd: SocketFd,
    pub interface: Rc<str>,
    interface_index: u32,
    pub interface_mac_address: [u8; 6],
}

impl RawSocket {
    pub fn bind(interface_name: &str, timeout: Option<Duration>) -> Result<Self, DhcpClientError> {
        use mac_address::mac_address_by_name;

        let fd = SocketFd::try_from(unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                libc::htons(libc::ETH_P_ALL as u16) as i32,
            )
        })?;

        if let Some(timeout_duration) = timeout {
            fd.set_socket_timeout(timeout_duration)?;
        }

        let interface_index = unsafe {
            libc::if_nametoindex(
                CString::new(interface_name)
                    .map_err(|err| std::io::Error::from(err))?
                    .as_ptr(),
            )
        };
        if interface_index == 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        let socket_address = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: libc::htons(libc::ETH_P_ALL as u16),
            sll_ifindex: interface_index as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0u8,
            sll_addr: [0u8; 8],
        };

        let binding_result = unsafe {
            libc::bind(
                *fd,
                &socket_address as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };

        if binding_result != 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        let interface: Rc<str> = interface_name.into();
        let interface_mac_address: [u8; 6] = mac_address_by_name(&interface)?
            .ok_or(DhcpClientError::InterfaceMissingMacAddress(Rc::clone(
                &interface,
            )))?
            .bytes();

        Ok(Self {
            fd,
            interface,
            interface_index,
            interface_mac_address,
        })
    }

    pub fn set_filter(&self, filter_code: &mut [libc::sock_filter]) -> std::io::Result<()> {
        let filter_program = libc::sock_fprog {
            len: filter_code.len() as u16,
            filter: filter_code.as_mut_ptr(),
        };

        let setting_fileter_result = unsafe {
            libc::setsockopt(
                *self.fd,
                SOL_SOCKET,
                SO_ATTACH_FILTER,
                &filter_program as *const libc::sock_fprog as *const c_void,
                std::mem::size_of::<libc::sock_fprog>() as u32,
            )
        };

        if setting_fileter_result != 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn set_filter_command(&self, filter_cmd: &str) -> Result<(), error::DhcpClientError> {
        let capture = Capture::from_device::<&str>(&self.interface)?.open()?;

        let mut filter_program = capture.compile(filter_cmd, true)?;

        self.set_filter(convert_pcap_bpf_program_to_libc_bpf_instructions(
            &mut filter_program,
        ))?;

        Ok(())
    }

    pub fn send_to(
        &self,
        frame_data: &[u8],
        destination_mac_addr: &[u8; 6],
    ) -> std::io::Result<usize> {
        let mut destination_addres = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: libc::htons(libc::ETH_P_ALL as u16),
            sll_ifindex: self.interface_index as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 6u8,
            sll_addr: [0; 8],
        };
        destination_addres.sll_addr[..6].copy_from_slice(destination_mac_addr);

        let send_result = unsafe {
            libc::sendto(
                *self.fd,
                frame_data.as_ptr() as *const c_void,
                frame_data.len(),
                0,
                &destination_addres as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };

        if send_result < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(send_result as usize)
        }
    }

    pub fn recv_from(&self) -> std::io::Result<(Vec<u8>, libc::sockaddr_ll)> {
        let mut frame_data: Vec<u8> = Vec::with_capacity(4096);
        let mut frame_source_addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut frame_source_addr_size =
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;

        let recived_lenght = unsafe {
            libc::recvfrom(
                *self.fd,
                frame_data.as_mut_ptr() as *mut c_void,
                frame_data.capacity(),
                0,
                &mut frame_source_addr as *mut libc::sockaddr_ll as *mut libc::sockaddr,
                &mut frame_source_addr_size as *mut libc::socklen_t,
            )
        };

        if recived_lenght < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            unsafe {
                frame_data.set_len(recived_lenght as usize);
            }
            Ok((frame_data, frame_source_addr))
        }
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(*self.fd);
        }
    }
}

fn convert_pcap_bpf_program_to_libc_bpf_instructions(
    pcap_program: &mut pcap::BpfProgram,
) -> &mut [libc::sock_filter] {
    unsafe {
        let libc_progam: &libc::sock_fprog =
            &*(pcap_program as *const _ as *const libc::sock_fprog);
        std::slice::from_raw_parts_mut(libc_progam.filter, libc_progam.len as usize)
    }
}
