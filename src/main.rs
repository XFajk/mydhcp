mod dhcp_help;
mod error;
mod netconfig_help;
mod socket_help;

use error::DhcpClientError;
use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
use log::{error, info};
use std::{env::args, io::{self, Write}, net::Ipv4Addr, rc::Rc};

use dhcp_help::*;
use socket_help::RawSocket;

use crate::netconfig_help::NetConfigManager;

fn main() {
    env_logger::init();

    let args: Vec<String> = args().collect();

    let client = DhcpClient::establish_dhcp_connection(&args);
    if let Err(e) = client {
        error!("Failed to establish DHCP connection: {}", e);
        panic!();
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
    Active {
        socket: RawSocket,
        transaction_id: u32,
        ip: Ipv4Addr,
        server_ip: Ipv4Addr,
        acknowledged_options: Rc<[DhcpOption]>,
        lease_time: std::time::Duration,
    },
}

impl DhcpClient {
    fn establish_dhcp_connection(args: &[String]) -> Result<Self, DhcpClientError> {
        DhcpClient::new()
            .connect(args)?
            .discover()?
            .receive_offer()?
            .request()?
            .receive_acknowledgement()?
            .activate()
    }

    fn new() -> Self {
        Self::Disconnected
    }

    fn connect(self, args: &[String]) -> Result<Self, DhcpClientError> {
        if let Self::Disconnected = self {
            info!(target: "mydhcp::connect", "Setting UP the DHCP Client");

            let interface_name = args
                .get(1)
                .ok_or(error::DhcpClientError::MissingInterface)?;

            info!(target: "mydhcp::connect", "- Creating a Socket for DHCP comunication on interface: {}", interface_name);
            let socket = RawSocket::bind(interface_name)?;
            socket.set_filter_command("udp port 68 or udp port 67")?;

            Ok(Self::Connected { socket })
        } else {
            Err(DhcpClientError::DhcpInvalidState)
        }
    }

    fn discover(self) -> Result<Self, error::DhcpClientError> {
        info!(target: "mydhcp::discover", "Preparing to send DHCP Discover packet");
        if let Self::Connected { socket } = self {
            let transaction_id = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis() as u32
                ^ std::process::id();
            info!(target: "mydhcp::discover", "- Constructed a transaction ID: {}", transaction_id);
            info!(target: "mydhcp::discover", "- Building the DHCP Discover packet");
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
            info!(target: "mydhcp::discover", "- Sending the DHCP Discover packet");
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
            info!(target: "mydhcp::receive_offer", "Waiting for DHCP Offer packet");
            let response = unsafe {
                Self::get_dhcp_response(
                    &socket,
                    transaction_id,
                    std::time::Duration::from_secs(10),
                )?
            };
            info!(target: "mydhcp::receive_offer", "- Received DHCP Offer packet");

            info!(target: "mydhcp::receive_offer", "- Parsing DHCP options from the response");
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
            info!(target: "mydhcp::receive_offer", "- DHCP Server IP address: {}", server_ip);

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
            info!(target: "mydhcp::request", "Preparing to send DHCP Request packet");
            info!(target: "mydhcp::request", "- Building the DHCP Request packet");
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

            info!(target: "mydhcp::request", "- Sending the DHCP Request packet");
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
            info!(target: "mydhcp::receive_acknowledgement", "Waiting for DHCP Acknowledgment packet");
            let acknowledgement = unsafe {
                Self::get_dhcp_response(
                    &socket,
                    transaction_id,
                    std::time::Duration::from_secs(10),
                )?
            };
            info!(target: "mydhcp::receive_acknowledgement", "- Received DHCP Acknowledgment packet");

            info!(target: "mydhcp::receive_acknowledgement", "- Parsing DHCP options from the acknowledgment");
            let dhcp_options = DhcpOption::parse_dhcp_options(&acknowledgement.dhcp_options)
                .ok_or(DhcpClientError::DhcpOptionParsingError)?;

            info!(target: "mydhcp::receive_acknowledgement", "- Analyzing differences DHCP options from the offer and acknowledgment");
            let differences = compare_dhcp_options(&dhcp_options, &offered_dhcp_options);
            println!("The following options were added or changed from the offer to the acknowledgment:");
            for diff in differences.iter() {
                println!("{:?} -> {:?}", diff.0, diff.1);
            }
            if !prompt_yes_no("Do you want to continue with the received options?") {
                return Err(DhcpClientError::DhcpResponseOptionsRejected);
            }

            let acknowledged_options = combine_dhcp_options(&dhcp_options, &offered_dhcp_options);

            Ok(DhcpClient::ReceivedAcknowledgment {
                socket,
                transaction_id,
                ip,
                server_ip,
                acknowledged_options,
            })
        } else {
            Err(DhcpClientError::DhcpInvalidState)
        }
    }
    fn activate(self) -> Result<Self, DhcpClientError> {
        if let DhcpClient::ReceivedAcknowledgment {
            socket,
            transaction_id,
            ip,
            server_ip,
            acknowledged_options,
        } = self
        {
            info!(target: "mydhcp::activate", "Activating the DHCP Client with the received configuration");

            let mask = match acknowledged_options
                .iter()
                .find(|x| matches!(x, DhcpOption::SubnetMask(_)))
                .ok_or(DhcpClientError::DhcpResponseOptionsMissingComponent(
                    "Subnet Mask".into(),
                ))? {
                DhcpOption::SubnetMask(mask) => *mask,
                _ => panic!(
                    "this branch will of code should never execute since the find method already check for a ServerId and and the ok_or handles if nothing is returned so there is no need to put something here"
                ),
            };
            info!(target: "mydhcp::activate", "- Subnet Mask: {}", mask);

            let dns_servers = match acknowledged_options
                .iter()
                .find(|x| matches!(x, DhcpOption::DomainNameServer(_)))
                .ok_or(DhcpClientError::DhcpResponseOptionsMissingComponent(
                    "Domain Name Server List".into(),
                ))? {
                DhcpOption::DomainNameServer(servers) => Rc::clone(servers),
                _ => panic!(
                    "this branch will of code should never execute since the find method already check for a ServerId and and the ok_or handles if nothing is returned so there is no need to put something here"
                ),
            };
            info!(target: "mydhcp::activate", "- DNS Servers: {:?}", dns_servers);

            let gateways = match acknowledged_options
                .iter()
                .find(|x| matches!(x, DhcpOption::Gateway(_)))
                .ok_or(DhcpClientError::DhcpResponseOptionsMissingComponent(
                    "Gateway List".into(),
                ))? {
                DhcpOption::Gateway(gates) => Rc::clone(gates),
                _ => panic!(
                    "this branch will of code should never execute since the find method already check for a ServerId and and the ok_or handles if nothing is returned so there is no need to put something here"
                ),
            };
            info!(target: "mydhcp::activate", "- Gateways: {:?}", gateways);

            let lease_time = *match acknowledged_options
                .iter()
                .find(|x| matches!(x, DhcpOption::IpAddressLeaseTime(_)))
                .ok_or(DhcpClientError::DhcpResponseOptionsMissingComponent(
                    "IP Address Lease Time".into(),
                ))? {
                DhcpOption::IpAddressLeaseTime(t) => t,
                _ => panic!(
                    "this branch will of code should never execute since the find method already check for a ServerId and and the ok_or handles if nothing is returned so there is no need to put something here"
                ),
            };
            info!(target: "mydhcp::activate", "- Lease Time: {} seconds", lease_time);

            info!(target: "mydhcp::activate", "- Configuring the network with the received options");
            let net_config = NetConfigManager::new()?;
            net_config.set_ip(&socket.interface, ip)?;
            net_config.set_mask(&socket.interface, mask)?;
            net_config.set_gateway(
                &socket.interface,
                gateways
                    .get(0)
                    .ok_or(DhcpClientError::GatewayListEmpty)?
                    .clone(),
            )?;
            net_config.set_dns(&dns_servers)?;
            net_config.enable(&socket.interface)?;

            Ok(DhcpClient::Active {
                socket,
                transaction_id,
                ip,
                server_ip,
                acknowledged_options,
                lease_time: std::time::Duration::from_secs(lease_time as u64),
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
fn compare_dhcp_options<'a>(
    new_options: &'a [DhcpOption],
    old_options: &'a [DhcpOption],
) -> Box<[(Option<&'a DhcpOption>, &'a DhcpOption)]> {
    use std::mem::discriminant;

    let mut differences: Vec<(Option<&DhcpOption>, &DhcpOption)> = Vec::new();

    for new_o in new_options {
        let old_o = old_options
            .iter()
            .find(|o| discriminant(*o) == discriminant(new_o));
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

fn combine_dhcp_options(
    new_options: &[DhcpOption],
    old_options: &[DhcpOption],
) -> Rc<[DhcpOption]> {
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

fn prompt_yes_no(prompt: &str) -> bool {
    print!("{} [y/n]: ", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
}
