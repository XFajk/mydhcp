use std::{
    ffi::CString,
    os::{fd::RawFd, raw::c_void}, rc::Rc,
};

use libc::{SO_ATTACH_FILTER, SOL_SOCKET};
use pcap::Capture;

use crate::error;

#[derive(Debug, Clone)]
pub struct RawSocket {
    fd: RawFd,
    pub interface: Rc<str>,
    interface_index: u32,
}

impl RawSocket {
    pub fn bind(interface_name: &str) -> std::io::Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                libc::htons(libc::ETH_P_ALL as u16) as i32,
            )
        };

        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let fd: RawFd = RawFd::from(fd);

        let interface_index =
            unsafe { libc::if_nametoindex(CString::new(interface_name)?.as_ptr()) };
        if interface_index == 0 {
            return Err(std::io::Error::last_os_error());
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
                fd,
                &socket_address as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };

        if binding_result != 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self {
            fd,
            interface: interface_name.into(),
            interface_index,
        })
    }

    pub fn set_filter(&self, filter_code: &mut [libc::sock_filter]) -> std::io::Result<()> {
        let filter_program = libc::sock_fprog {
            len: filter_code.len() as u16,
            filter: filter_code.as_mut_ptr(),
        };

        let setting_fileter_result = unsafe {
            libc::setsockopt(
                self.fd,
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
        let capture = Capture::from_device::<&str>(&self.interface)?
            .open()?;

        let mut filter_program = capture
            .compile(filter_cmd, true)?;

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
                self.fd,
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
                self.fd,
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
            libc::close(self.fd);
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
