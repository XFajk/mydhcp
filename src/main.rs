mod dhcp_help;
mod error;
mod socket_help;

use dhcp_help::*;
use error::DhcpClientError;
use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
use std::{env::args, net::Ipv4Addr, rc::Rc};

use socket_help::RawSocket;

fn main() {
    let args: Vec<String> = args().collect();

    let client = DhcpClient::establish_dhcp_connection(&args); 
    match client {
        Ok(_) => {},
        Err(e) => panic!("{}", e)
    }

    println!("{:#?}", client);
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
        server_ip: Ipv4Addr,
        dhcp_options: Rc<[DhcpOption]>,
    },
    Requesting {
        socket: RawSocket,
        transaction_id: u32,
        ip: Ipv4Addr,
        server_ip: Ipv4Addr,
        offered_dhcp_options: Rc<[DhcpOption]>,
    },
    ReceivedAcknowledgment {
        socket: RawSocket,
        transaction_id: u32,
        ip: Ipv4Addr,
        server_ip: Ipv4Addr,
        acknowledged_options: Rc<[DhcpOption]>,
    },
    Active,
}

impl DhcpClient {
    fn establish_dhcp_connection(args: &[String]) -> Result<Self, DhcpClientError> {
        DhcpClient::new().connect(args)?.discover()?.receive_offer()?.request()
    }

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
                socket.interface_mac_address,
                [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            )
            .ipv4([0u8, 0u8, 0u8, 0u8], [0xffu8, 0xffu8, 0xffu8, 0xffu8], 10)
            .udp(68, 67);

            let dhcp_payload = DhcpPayload::discover(&socket.interface, transaction_id, None);
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
            let response = unsafe {
                Self::get_dhcp_response(
                    &socket,
                    transaction_id,
                    std::time::Duration::from_secs(10),
                )?
            };

            let dhcp_options = DhcpOption::parse_dhcp_options(&response.dhcp_options)
                .ok_or(DhcpClientError::DhcpOptionParsingError)?;

            let server_ip = match (*dhcp_options)
                .iter()
                .find(|x| matches!(x, DhcpOption::ServerId(_)))
                .ok_or(DhcpClientError::DhcpResponseOptionsMissingComponent(
                    "Server IP address".into(),
                ))? {
                DhcpOption::ServerId(ip) => *ip,
                _ => panic!(
                    "this branch will of code should never execute since the find method already check for a ServerId and and the ok_or handles if nothing is returned so there is no need to put something here"
                ),
            };

            // let mask = match dhcp_options
            //     .iter()
            //     .find(|x| matches!(x, DhcpOption::SubnetMask(_)))
            //     .ok_or(DhcpClientError::DhcpResponseOptionsMissingComponent(
            //         "Subnet Mask".into(),
            //     ))? {
            //     DhcpOption::SubnetMask(mask) => *mask,
            //     _ => panic!(
            //         "this branch will of code should never execute since the find method already check for a ServerId and and the ok_or handles if nothing is returned so there is no need to put something here"
            //     ),
            // };

            // let dns_servers = match dhcp_options
            //     .iter()
            //     .find(|x| matches!(x, DhcpOption::DomainNameServer(_)))
            //     .ok_or(DhcpClientError::DhcpResponseOptionsMissingComponent(
            //         "Domain Name Server List".into(),
            //     ))? {
            //     DhcpOption::DomainNameServer(servers) => Rc::clone(servers),
            //     _ => panic!(
            //         "this branch will of code should never execute since the find method already check for a ServerId and and the ok_or handles if nothing is returned so there is no need to put something here"
            //     ),
            // };

            // let gateways = match dhcp_options
            //     .iter()
            //     .find(|x| matches!(x, DhcpOption::Gateway(_)))
            //     .ok_or(DhcpClientError::DhcpResponseOptionsMissingComponent(
            //         "Gateway List".into(),
            //     ))? {
            //     DhcpOption::Gateway(gates) => Rc::clone(gates),
            //     _ => panic!(
            //         "this branch will of code should never execute since the find method already check for a ServerId and and the ok_or handles if nothing is returned so there is no need to put something here"
            //     ),
            // };

            // let lease_time = *match dhcp_options
            //     .iter()
            //     .find(|x| matches!(x, DhcpOption::IpAddressLeaseTime(_)))
            //     .ok_or(DhcpClientError::DhcpResponseOptionsMissingComponent(
            //         "IP Address Lease Time".into(),
            //     ))? {
            //     DhcpOption::IpAddressLeaseTime(t) => t,
            //     _ => panic!(
            //         "this branch will of code should never execute since the find method already check for a ServerId and and the ok_or handles if nothing is returned so there is no need to put something here"
            //     ),
            // };

            Ok(Self::ReceivedOffer {
                socket,
                transaction_id,
                ip: response.yiaddr,
                server_ip,
                dhcp_options,
            })
        } else {
            Err(DhcpClientError::DhcpInvalidState)
        }
    }

    fn request(self) -> Result<Self, DhcpClientError> {
        if let DhcpClient::ReceivedOffer {
            socket,
            transaction_id,
            ip,
            server_ip,
            dhcp_options,
        } = self
        {
            let packet_builder = PacketBuilder::ethernet2(
                socket.interface_mac_address,
                [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            )
            .ipv4(ip.octets(), server_ip.octets(), 10)
            .udp(68, 67);

            let dhcp_payload =
                DhcpPayload::request(&socket.interface, transaction_id, ip, server_ip);
            let raw_payload = dhcp_payload.to_bytes();

            let mut raw_packet = Vec::<u8>::with_capacity(packet_builder.size(raw_payload.len()));

            packet_builder.write(&mut raw_packet, &raw_payload)?;
            socket.send_to(
                &raw_packet,
                &[0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8],
            )?;

            Ok(DhcpClient::Requesting {
                socket,
                transaction_id,
                ip,
                server_ip,
                offered_dhcp_options: dhcp_options,
            })
        } else {
            Err(DhcpClientError::DhcpInvalidState)
        }
    }

    fn receive_acknowledgement(self) -> Result<Self, DhcpClientError> {
        if let DhcpClient::Requesting {
            socket,
            transaction_id,
            ip,
            server_ip,
            offered_dhcp_options,
        } = self
        {
            let acknowledgement = unsafe {
                Self::get_dhcp_response(
                    &socket,
                    transaction_id,
                    std::time::Duration::from_secs(10),
                )?
            };

            let dhcp_options = DhcpOption::parse_dhcp_options(&acknowledgement.dhcp_options)
                .ok_or(DhcpClientError::DhcpOptionParsingError)?;
            
            let differences = compare_dhcp_options(&dhcp_options, &offered_dhcp_options);
            for diff in differences {
                println!("{:?} -> {:?}", diff.0, diff.1);
            }
            // TODO add a propt here if the user is ok with these changes
            
            let acknowledged_options = combine_dhcp_options(&dhcp_options, &offered_dhcp_options);

            Ok(DhcpClient::ReceivedAcknowledgment {
                socket,
                transaction_id,
                ip,
                server_ip,
                acknowledged_options
            })
        } else {
            Err(DhcpClientError::DhcpInvalidState)
        }
    } 
}

impl DhcpClient {
    /// REDO! this code is really bad it is very unsafe it only check
    /// if the packet is UDP and that is it and I think it should do more checks
    /// also it should probably return more than one packet
    unsafe fn get_dhcp_response(
        socket: &RawSocket,
        transaction_id: u32,
        time_out: std::time::Duration,
    ) -> Result<DhcpPayload, error::DhcpClientError> {
        let is_desired_packet = |packet: SlicedPacket| -> Option<DhcpPayload> {
            let dhcp_payload: Option<DhcpPayload> = match packet.transport {
                Some(TransportSlice::Udp(upd_slice)) => unsafe {
                    DhcpPayload::from_bytes(upd_slice.payload())
                },
                _ => return None,
            };

            let dhcp_payload = match dhcp_payload {
                Some(value) => value,
                None => return None,
            };

            if dhcp_payload.xid != transaction_id {
                return None; 
            }

            Some(dhcp_payload) 
        };

        let elapsed_time = std::time::Instant::now();

        while elapsed_time.elapsed() < time_out {
            let (data, _) = socket.recv_from()?;
            let data = Rc::from(data);

            match SlicedPacket::from_ethernet(&data) {
                Ok(parsed) => {
                    if let Some(payload) = is_desired_packet(parsed) {
                        return Ok(payload);
                    }
                }
                Err(err) => return Err(err.into()),
            }
        }
        return Err(error::DhcpClientError::TimedOut(time_out));
    }
}


/// This Function checks new options and old options and if something is different in the new options or if there is a completely new option
/// then we add it to the differences that are returned at the end
fn compare_dhcp_options<'a>(new_options: &'a[DhcpOption], old_options: &'a[DhcpOption]) -> Box<[(Option<&'a DhcpOption>, &'a DhcpOption)]> {
    use std::mem::discriminant;

    let mut differences: Vec<(Option<&DhcpOption>, &DhcpOption)> = Vec::new();

    for new_o in new_options {
        let old_o = old_options.iter().find(|o| discriminant(*o) == discriminant(new_o));
        match old_o {
            Some(old_o) => {
                if new_o != old_o {
                    differences.push((Some(old_o), new_o));
                }
            }
            None => {
                differences.push((None, new_o));
            }
        }
    }

    differences.into_boxed_slice()
}

fn combine_dhcp_options(new_options: &[DhcpOption], old_options: &[DhcpOption]) -> Rc<[DhcpOption]> {
    use std::mem::discriminant;

    let mut result: Vec<DhcpOption> = Vec::from(new_options);

    for old_o in old_options {
        let d = discriminant(old_o);
        if !result.iter().any(|o| discriminant(o) == d) {
            result.push(old_o.clone());
        }
    }

    result.into()
}