mod dhcp_help;
mod socket_help;

use dhcp_help::*;
use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
use mac_address::mac_address_by_name;
use std::env::args;

use socket_help::RawSocket;

fn main() {
    let args: Vec<String> = args().collect();

    let interface_name = args.get(1).expect("no interface was provided");

    let dhcp_socket = RawSocket::bind(interface_name).expect("could not create a raw socket");
    dhcp_socket
        .set_filter_command("udp port 68 or udp port 67")
        .unwrap();

    let packet_builder = PacketBuilder::ethernet2(
        mac_address_by_name(&interface_name)
            .unwrap()
            .unwrap()
            .bytes(),
        [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    )
    .ipv4([0u8, 0u8, 0u8, 0u8], [0xffu8, 0xffu8, 0xffu8, 0xffu8], 10)
    .udp(68, 67);

    let dhcp_transaction_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u32
        ^ std::process::id();
    let dhcp_payload = DhcpPayload::discover(interface_name, dhcp_transaction_id);
    let raw_payload = unsafe { any_as_u8_slice(&dhcp_payload) };

    let mut raw_packet = Vec::<u8>::with_capacity(packet_builder.size(raw_payload.len()));

    packet_builder.write(&mut raw_packet, &raw_payload).unwrap();

    dhcp_socket
        .send_to(
            &raw_packet,
            &[0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8],
        )
        .unwrap();

    loop {
        let data = dhcp_socket.recv_from().unwrap();
    }
}

fn get_dhcp_response(
    socket: &RawSocket,
    transaction_id: u32,
    time_out: std::time::Duration,
) -> std::io::Result<Vec<u8>> {
    let elapsed_time = std::time::Instant::now();
    loop {
        if elapsed_time.elapsed() > time_out {
            break;
        }
        let (data, _) = socket.recv_from()?;
        match SlicedPacket::from_ethernet(&data) {
            Ok(parsed) => {
                if let Some(TransportSlice::Udp(upd_slice)) = parsed.transport {
                    let dhcp_payload = upd_slice.payload();
                } 
            }
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    err.to_string(),
                ));
            }
        }
    }

    todo!();
}
