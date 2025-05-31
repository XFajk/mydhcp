mod dhcp_help;
mod socket_help;

use dhcp_help::*;
use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
use mac_address::mac_address_by_name;
use std::{env::args, rc::Rc};

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
    let raw_payload = dhcp_payload.to_bytes();

    let mut raw_packet = Vec::<u8>::with_capacity(packet_builder.size(raw_payload.len()));

    packet_builder.write(&mut raw_packet, &raw_payload).unwrap();

    dhcp_socket
        .send_to(
            &raw_packet,
            &[0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8],
        )
        .unwrap();

    let response = get_dhcp_response(
        &dhcp_socket,
        dhcp_transaction_id,
        std::time::Duration::from_secs(10),
    )
    .expect("Failed to capture DHCP Response");

    let response = match SlicedPacket::from_ethernet(&response) {
        Ok(sliced) => unsafe { DhcpPayload::from_sliced_packet(sliced) },
        Err(err) => panic!("Failed to parse ethernet packet: {}", err),
    }
    .unwrap();

    let my_ip = response.yiaddr;
    let dhcp_options = DhcpOption::parse_dhcp_options(&response.dhcp_options).unwrap();
    println!("My IP address {}", my_ip);
    println!("DHCP options: {:?}", dhcp_options);

}

fn get_dhcp_response(
    socket: &RawSocket,
    transaction_id: u32,
    time_out: std::time::Duration,
) -> std::io::Result<Rc<[u8]>> {
    let is_desired_packet = |packet: SlicedPacket| -> bool {
        let dhcp_payload: Option<DhcpPayload> = match packet.transport {
            Some(TransportSlice::Udp(upd_slice)) => unsafe {
                DhcpPayload::from_bytes(upd_slice.payload())
            },
            _ => return false,
        };

        let dhcp_payload = match dhcp_payload {
            Some(value) => value,
            None => return false,
        };

        if dhcp_payload.xid != transaction_id {
            return false;
        }

        true
    };

    let elapsed_time = std::time::Instant::now();

    loop {
        if elapsed_time.elapsed() > time_out {
            break Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "The time for capturing a response from a DHCP Server has ran out",
            ));
        }
        let (data, _) = socket.recv_from()?;
        let data = Rc::from(data);

        match SlicedPacket::from_ethernet(&data) {
            Ok(parsed) => {
                if is_desired_packet(parsed) {
                    break Ok(Rc::clone(&data));
                }
            }
            Err(err) => return Err(std::io::Error::other(err.to_string())),
        }
    }
}
