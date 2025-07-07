use libc::{ioctl, AF_INET, AF_NETLINK, IFF_UP};
use std::{ffi::{c_void, CString}, net::Ipv4Addr, os::fd::RawFd};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct RtMsg {
    rtm_family: u8,
    rtm_dst_len: u8,
    rtm_src_len: u8,
    rtm_tos: u8,
    rtm_table: u8,
    rtm_protocol: u8,
    rtm_scope: u8,
    rtm_type: u8,
    rtm_flags: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct RtAttr {
    rta_len: u16,
    rta_type: u16,
}

/// Manages network configuration using a netlink socket.
pub struct NetConfigManager {
    netlink_socket: RawFd,
    control_socket: RawFd,
}

impl NetConfigManager {
    /// Creates a new NetConfigManager by opening a netlink socket.
    pub fn new() -> std::io::Result<Self> {
        let netlink_socket =
            unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };

        if netlink_socket < 0 {
            unsafe {
                libc::close(netlink_socket);
            }
            return Err(std::io::Error::last_os_error());
        }

        let mut nl_addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        nl_addr.nl_family = AF_NETLINK as u16;

        let binding_result = unsafe {
            libc::bind(
                netlink_socket,
                &nl_addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };

        if binding_result < 0 {
            unsafe {
                libc::close(netlink_socket);
            }
            return Err(std::io::Error::last_os_error());
        }

        let control_socket =
            unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::NETLINK_ROUTE) };

        if control_socket < 0 {
            unsafe {
                libc::close(netlink_socket);
                libc::close(control_socket);
            }
            return Err(std::io::Error::last_os_error());
        }

        Ok(NetConfigManager {
            netlink_socket,
            control_socket,
        })
    }

    pub fn set_ip(&self, interface_name: &str, ip: Ipv4Addr) -> std::io::Result<()> {
        let interface_name = CString::new(interface_name)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        let name_bytes = interface_name.as_bytes_with_nul();
        let len = ifr.ifr_name.len().min(name_bytes.len());
        ifr.ifr_name[..len].copy_from_slice(&name_bytes[..len]);

        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        addr.sin_family = AF_INET as u16;
        addr.sin_addr.s_addr = u32::from(ip).to_be();

        unsafe {
            let ifr_addr_ptr = &mut ifr.ifr_ifru.ifru_addr as *mut libc::sockaddr;
            std::ptr::copy_nonoverlapping(
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                ifr_addr_ptr,
                1,
            );
        }

        let op_result =
            unsafe { ioctl(self.control_socket, libc::SIOCSIFADDR, &mut ifr as *mut _) };

        if op_result < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(())
    }

    pub fn set_mask(&self, interface_name: &str, mask: Ipv4Addr) -> std::io::Result<()> {
        let interface_name = CString::new(interface_name)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        let name_bytes = interface_name.as_bytes_with_nul();
        let len = ifr.ifr_name.len().min(name_bytes.len());
        ifr.ifr_name[..len].copy_from_slice(&name_bytes[..len]);

        let mut mask_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        mask_addr.sin_family = AF_INET as u16;
        mask_addr.sin_addr.s_addr = u32::from(mask).to_be();

        unsafe {
            let ifr_addr_ptr = &mut ifr.ifr_ifru.ifru_addr as *mut libc::sockaddr;
            std::ptr::copy_nonoverlapping(
                &mask_addr as *const libc::sockaddr_in as *const libc::sockaddr,
                ifr_addr_ptr,
                1,
            );
        }

        let op_result = unsafe {
            ioctl(
                self.control_socket,
                libc::SIOCSIFNETMASK,
                &mut ifr as *mut _,
            )
        };

        if op_result < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(())
    }

    pub fn enable(&self, interface_name: &str) -> std::io::Result<()> {
        let interface_name = CString::new(interface_name)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        let name_bytes = interface_name.as_bytes_with_nul();
        let len = ifr.ifr_name.len().min(name_bytes.len());
        ifr.ifr_name[..len].copy_from_slice(&name_bytes[..len]);

        let res = unsafe {
            ioctl(
                self.control_socket,
                libc::SIOCGIFFLAGS,
                &mut ifr as *mut _,
            )
        };
        if res < 0 {
            return Err(std::io::Error::last_os_error());
        }

        unsafe {
            // ifr_ifru is a union, so access as flags
            let flags_ptr = &mut ifr.ifr_ifru as *mut _ as *mut libc::c_short;
            *flags_ptr |= libc::IFF_UP as libc::c_short;
        }

        // Set the flags back
        let res = unsafe {
            ioctl(
                self.control_socket,
                libc::SIOCSIFFLAGS,
                &mut ifr as *mut _,
            )
        };
        if res < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(())
    }

    pub fn set_gateway(&self, interface_index: u32, gateway: Ipv4Addr) -> std::io::Result<()> {
        /// Converts a reference to a struct into a boxed slice of its bytes.
        /// # Safety
        /// Only use with plain-old-data structs (no pointers, no drop logic).
        unsafe fn struct_as_bytes<T>(s: &T) -> Box<[u8]> {
            let size = std::mem::size_of::<T>();
            let ptr = s as *const T as *const u8;
            unsafe {
                std::slice::from_raw_parts(ptr, size)
                    .to_vec()
                    .into_boxed_slice()
            }
        }

        let mut header: libc::nlmsghdr = libc::nlmsghdr {
            nlmsg_len: 0,
            nlmsg_type: libc::RTM_NEWROUTE,
            nlmsg_seq: 1,
            nlmsg_flags: (libc::NLM_F_REQUEST | libc::NLM_F_CREATE | libc::NLM_F_EXCL) as u16,
            nlmsg_pid: 0,
        };

        let message: RtMsg = RtMsg {
            rtm_family: libc::AF_INET as u8,
            rtm_dst_len: 0u8,
            rtm_src_len: 0u8,
            rtm_tos: 0u8,
            rtm_table: libc::RT_TABLE_MAIN as u8,
            rtm_protocol: libc::RTPROT_STATIC,
            rtm_scope: libc::RT_SCOPE_UNIVERSE,
            rtm_type: libc::RTN_UNICAST,
            rtm_flags: 0u32,
        };

        let gateway_attribute: RtAttr = RtAttr {
            rta_len: (std::mem::size_of::<RtAttr>() + 4) as u16,
            rta_type: libc::RTA_GATEWAY,
        };

        let interface_attribute: RtAttr = RtAttr {
            rta_len: (std::mem::size_of::<RtAttr>() + 4) as u16,
            rta_type: libc::RTA_OIF,
        };

        let gateway_addr = u32::from(gateway);

        let mut buffer: Vec<u8> = Vec::with_capacity(
            std::mem::size_of_val(&header)
                + std::mem::size_of_val(&message)
                + std::mem::size_of::<RtAttr>() * 2
                + 8, // these 8 bytes are for the added gatway address and intreface index
        );

        unsafe {
            buffer.extend_from_slice(&struct_as_bytes(&header));
            buffer.extend_from_slice(&struct_as_bytes(&message));
            buffer.extend_from_slice(&struct_as_bytes(&gateway_attribute));
            buffer.extend_from_slice(&gateway_addr.to_be_bytes());
            buffer.extend_from_slice(&struct_as_bytes(&interface_attribute));
            buffer.extend_from_slice(&interface_index.to_be_bytes());
        }

        let send_result = unsafe {
            libc::send(
                self.netlink_socket,
                &buffer as *const _ as *const c_void,
                buffer.len(),
                0
            )
        };

        if send_result < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(())
    }
}

impl Drop for NetConfigManager {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.control_socket);
            libc::close(self.netlink_socket);
        }
    }
}
