mod dhcp_help;
mod socket_help;

use std::env::args;

use socket_help::RawSocket;

fn main() {
    let args: Vec<String> = args().collect();

    let dhcp_socket = RawSocket::bind(args.get(1).expect("no interface was provided")).expect("could not create a raw socket");
    dhcp_socket.set_filter_command("udp port 68 and udp port 67").unwrap();

    loop {
        let data = dhcp_socket.recv_from().unwrap();
        println!("{:?}", data);
    }
}
