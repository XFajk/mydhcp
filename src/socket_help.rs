use std::{
    ffi::CString,
    os::{fd::RawFd, raw::c_void},
    ptr::null_mut,
};

use libc::{SO_ATTACH_FILTER, SOL_SOCKET};
use pcap::Capture;
pub struct RawSocket {
    fd: RawFd,
    device: Box<str>,
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

        let socket_addres = libc::sockaddr_ll {
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
                &socket_addres as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };

        if binding_result != 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self {
            fd,
            device: interface_name.into(),
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

    pub fn set_filter_command(&self, filter_cmd: &str) -> std::io::Result<()> {
        let capture = Capture::from_device::<&str>(&self.device)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?
            .open()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        let filter_program = capture
            .compile(filter_cmd, true)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        self.set_filter(&mut convert_pcap_bpf_program_to_libc_bpf_instructions(&filter_program))?;

        Ok(())
    }

    pub fn send_to() -> std::io::Result<()> {
        todo!()
    }

    pub fn recv_from(&self) -> std::io::Result<(Vec<u8>, libc::sockaddr_ll)> {
        let mut msg_data: Vec<u8> = Vec::with_capacity(4096);
        let mut msg_source_addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut msg_source_addr_size = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;

        let recived_lenght = unsafe {
            libc::recvfrom(
                self.fd,
                msg_data.as_mut_ptr() as *mut c_void,
                msg_data.capacity(),
                0,
                &mut msg_source_addr as *mut libc::sockaddr_ll as *mut libc::sockaddr,
                &mut msg_source_addr_size as *mut libc::socklen_t,
            )
        };

        if recived_lenght < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            unsafe {
                msg_data.set_len(recived_lenght as usize);
            }
            Ok((msg_data, msg_source_addr))
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

fn convert_pcap_bpf_program_to_libc_bpf_instructions(pcap_program: &pcap::BpfProgram) -> Vec<libc::sock_filter> {
    unsafe {
        let libc_progam: &libc::sock_fprog = &*(pcap_program as *const _ as *const libc::sock_fprog);
        Vec::from_raw_parts(libc_progam.filter, libc_progam.len as usize, libc_progam.len as usize)
    }
}

pub unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts((p as *const T) as *const u8, ::core::mem::size_of::<T>()) }
}
