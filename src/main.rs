mod dhcp_help;
mod error;
mod socket_help;

use dhcp_help::*;
use error::DhcpClientError;
use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
use mac_address::mac_address_by_name;
use std::{env::args, net::Ipv4Addr, rc::Rc};

use socket_help::RawSocket;

fn main() -> Result<(), DhcpClientError> {
    let args: Vec<String> = args().collect();

    let client = DhcpClient::new()
        .connect(&args)?
        .discover()?
        .receive_offer()?;

    println!("{:#?}", client);

    Ok(())
}

#[derive(Debug, Clone)]
enum DhcpClient {
    Disconnected,
    Connected {
        socket: RawSocket,
    },
    Discovering {
        socket: RawSocket,
        transaction_id: u32,
    },
    ReceivedOffer {
        socket: RawSocket,
        transaction_id: u32,
        ip: Ipv4Addr,
        dhcp_options: Rc<[DhcpOption]>,
    },
}

impl DhcpClient {
    fn new() -> Self {
        Self::Disconnected
    }

    fn connect(self, args: &[String]) -> Result<Self, DhcpClientError> {
        if let Self::Disconnected = self {
            let interface_name = args
                .get(1)
                .ok_or(error::DhcpClientError::MissingInterface)?;

            let socket = RawSocket::bind(interface_name)?;
            socket.set_filter_command("udp port 68 or udp port 67")?;

            Ok(Self::Connected { socket })
        } else {
            Err(DhcpClientError::DhcpInvalidState)
        }
    }

    fn discover(self) -> Result<Self, error::DhcpClientError> {
        if let Self::Connected { socket } = self {
            let transaction_id = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis() as u32
                ^ std::process::id();

            let packet_builder = PacketBuilder::ethernet2(
                mac_address_by_name(&socket.interface)?
                    .ok_or(DhcpClientError::InterfaceMissingMacAddress(Rc::clone(&socket.interface)))? 
                    .bytes(),
                [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            )
            .ipv4([0u8, 0u8, 0u8, 0u8], [0xffu8, 0xffu8, 0xffu8, 0xffu8], 10)
            .udp(68, 67);

            let dhcp_payload = DhcpPayload::discover(&socket.interface, transaction_id);
            let raw_payload = dhcp_payload.to_bytes();

            let mut raw_packet = Vec::<u8>::with_capacity(packet_builder.size(raw_payload.len()));

            packet_builder.write(&mut raw_packet, &raw_payload)?;
            socket.send_to(
                &raw_packet,
                &[0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8],
            )?;

            Ok(Self::Discovering {
                socket,
                transaction_id,
            })
        } else {
            Err(DhcpClientError::DhcpInvalidState)
        }
    }

    fn receive_offer(self) -> Result<Self, DhcpClientError> {
        if let Self::Discovering {
            socket,
            transaction_id,
        } = self
        {
            let response = Self::get_dhcp_response(
                &socket,
                transaction_id,
                std::time::Duration::from_secs(10),
            )?;

            let response = match SlicedPacket::from_ethernet(&response) {
                Ok(sliced) => unsafe { DhcpPayload::from_sliced_packet(sliced) },
                Err(err) => panic!("Failed to parse ethernet packet: {}", err),
            }
            .ok_or(DhcpClientError::DhcpConstructionError)?;

            Ok(Self::ReceivedOffer {
                socket,
                transaction_id,
                ip: response.yiaddr,
                dhcp_options: DhcpOption::parse_dhcp_options(&response.dhcp_options)
                    .ok_or(DhcpClientError::DhcpOptionParsingError)?,
            })
        } else {
            Err(DhcpClientError::DhcpInvalidState)
        }
    }

    fn get_dhcp_response(
        socket: &RawSocket,
        transaction_id: u32,
        time_out: std::time::Duration,
    ) -> Result<Rc<[u8]>, error::DhcpClientError> {
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
                break Err(error::DhcpClientError::TimedOut(time_out));
            }
            let (data, _) = socket.recv_from()?;
            let data = Rc::from(data);

            match SlicedPacket::from_ethernet(&data) {
                Ok(parsed) => {
                    if is_desired_packet(parsed) {
                        break Ok(Rc::clone(&data));
                    }
                }
                Err(err) => return Err(err.into()),
            }
        }
    }
}
