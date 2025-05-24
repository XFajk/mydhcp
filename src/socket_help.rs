use std::{ffi::CString, os::{fd::RawFd, raw::c_void}};


pub struct RawSocket {
    fd: RawFd,
}

impl RawSocket {
    pub fn new(interface_name: &str) -> std::io::Result<Self> {
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

        let interface_index = unsafe { libc::if_nametoindex(CString::new(interface_name)?.as_ptr()) };
        if interface_index == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let socket_addr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: libc::htons(libc::ETH_P_ALL as u16),
            sll_ifindex: interface_index as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0u8,
            sll_addr: [0u8; 8],
        };

        // if libc::bind(fd_) != 0 {}

        Ok(Self { fd })
    }
}

pub unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts((p as *const T) as *const u8, ::core::mem::size_of::<T>()) }
}
