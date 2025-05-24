mod dhcp_help;
mod socket_help;

use std::{ffi::c_int, net::{self, UdpSocket}, os::{fd::{AsRawFd, RawFd}, raw::c_void}};
use libc::{self, SOL_SOCKET, SO_BINDTODEVICE};

fn main() {
    let dhcp_socket: UdpSocket = UdpSocket::bind("0.0.0.0:68").unwrap();
    dhcp_socket.set_broadcast(true).unwrap();
    socket_set_device(dhcp_socket.as_raw_fd(), "wlp2s0").unwrap();

    let packet = dhcp_help::DhcpPacket::discover();
    dhcp_socket
        .send_to(unsafe { any_as_u8_slice(&packet) }, "255.255.255.255:67")
        .expect("failed to send data");

    let mut big_buf: [u8; 10000] = [0; 10000];
    dhcp_socket.recv_from(&mut big_buf).expect("failed to read data");

    println!("{:?}", big_buf);
}

fn socket_set_device(socket_fd: RawFd, interface_name: &str) -> std::io::Result<()> {
    let mut interface_name = interface_name.as_bytes().to_vec();
    interface_name.push(0);
    let operation_result = unsafe {
        libc::setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, interface_name.as_ptr() as *const c_void, interface_name.len() as libc::socklen_t)
    };

    if operation_result != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts((p as *const T) as *const u8, ::core::mem::size_of::<T>()) }
}
