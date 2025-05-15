mod dhcp_help;

use std::net::{self, UdpSocket};

fn main() {
    let dhcp_socket: UdpSocket = UdpSocket::bind("0.0.0.0:68").unwrap();
    dhcp_socket.set_broadcast(true).unwrap();

    let packet = dhcp_help::DhcpPacket::discover();
    dhcp_socket.send_to(unsafe { any_as_u8_slice(&packet) }, "255.255.255.255:67").expect("failed to send data");
    let mut big_buf: [u8; 2048] = [0; 2048];
    dhcp_socket.recv(&mut big_buf).unwrap();
    println!("{:?}", big_buf);
}

unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::core::slice::from_raw_parts((p as *const T) as *const u8, ::core::mem::size_of::<T>())
}
