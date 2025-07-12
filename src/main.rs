mod dhcp_help;
mod error;
mod netconfig_help;
mod socket_help;

use core::panic;
use error::DhcpClientError;
use etherparse::{PacketBuilder, SlicedPacket};
use log::{error, info, warn};
use std::{
    env::args,
    net::Ipv4Addr,
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
};

use dhcp_help::*;
use socket_help::RawSocket;

use crate::netconfig_help::NetConfigManager;

static SHOULD_SHUTDOWN: AtomicBool = AtomicBool::new(false);

fn main() {
    env_logger::init();

    // Clone the flag to move into the signal handler
    if let Err(e) = ctrlc::set_handler(|| {
        info!("SIGINT received! Setting shutdown flag. The process will shutdown gracefully soon");
        SHOULD_SHUTDOWN.store(true, Ordering::SeqCst);
    }) {
        error!("Failed to set Ctrl-C handler: {}", e);
        std::process::exit(1);
    }

    let args: Vec<String> = args().collect();
    while !SHOULD_SHUTDOWN.load(Ordering::SeqCst) {
        let client = DhcpClient::establish_dhcp_connection(&args);

        let mut client = match client {
            Ok(client) => client,
            Err(e) => {
                error!("Failed to establish DHCP connection: {}", e);
                continue; // Retry on error
            }
        };

        info!("DHCP connection established successfully.");
        println!("{:#?}", client);

        while !SHOULD_SHUTDOWN.load(Ordering::SeqCst) {
            let possibly_new_client = client.keep_track();
            match possibly_new_client {
                Some(new_client) => {
                    client = new_client;
                    info!("DHCP lease renewed successfully.");
                }
                None => {
                    error!("DHCP lease expired or could not be renewed, reconnecting...");
                    break; // Exit the loop if lease cannot be renewed
                }
            }
        }
    }
}

#[derive(Debug)]
enum DhcpClient {
    Disconnected,
    Connected {
        socket: Rc<RawSocket>,
    },
    Discovering {
        socket: Rc<RawSocket>,
        transaction_id: u32,
    },
    ReceivedOffer {
        socket: Rc<RawSocket>,
        transaction_id: u32,
        ip: Ipv4Addr,
        server_ip: Ipv4Addr,
        dhcp_options: Rc<[DhcpOption]>,
    },
    Requesting {
        socket: Rc<RawSocket>,
        transaction_id: u32,
        ip: Ipv4Addr,
        server_ip: Ipv4Addr,
        offered_dhcp_options: Rc<[DhcpOption]>,
    },
    ReceivedAcknowledgment {
        socket: Rc<RawSocket>,
        transaction_id: u32,
        ip: Ipv4Addr,
        server_ip: Ipv4Addr,
        acknowledged_options: Rc<[DhcpOption]>,
    },
    Active {
        socket: Rc<RawSocket>,
        transaction_id: u32,
        ip: Ipv4Addr,
        server_ip: Ipv4Addr,
        acknowledged_options: Rc<[DhcpOption]>,
        renewal_deadline: std::time::Instant,
        rebinding_deadline: std::time::Instant,
        expiration_deadline: std::time::Instant,
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

    fn retry_requesting(self) -> Result<Self, DhcpClientError> {
        self.request()?.receive_acknowledgement()?.activate()
    }

    fn new() -> Self {
        Self::Disconnected
    }

    fn connect(self, args: &[String]) -> Result<Self, DhcpClientError> {
        shutdown_on_signal();
        if let Self::Disconnected = self {
            info!(target: "mydhcp::connect", "Setting UP the DHCP Client");

            let interface_name = args
                .get(1)
                .ok_or(error::DhcpClientError::MissingInterface)
                .unwrap_or_else(|err| {
                    error!("FATAL: {}", err);
                    std::process::exit(1);
                });

            info!(target: "mydhcp::connect", "- Creating a Socket for DHCP comunication on interface: {}", interface_name);
            let socket = Rc::new(RawSocket::bind(interface_name)?);
            socket.set_filter_command("udp port 68 or udp port 67")?;

            Ok(Self::Connected { socket })
        } else {
            Err(DhcpClientError::DhcpInvalidState)
        }
    }

    fn discover(self) -> Result<Self, error::DhcpClientError> {
        shutdown_on_signal();
        if let Self::Connected { ref socket } = self {
            info!(target: "mydhcp::discover", "Preparing to send DHCP Discover packet");
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
                socket: Rc::clone(socket),
                transaction_id,
            })
        } else {
            Err(DhcpClientError::DhcpInvalidState)
        }
    }

    fn receive_offer(self) -> Result<Self, DhcpClientError> {
        shutdown_on_signal();
        if let Self::Discovering {
            ref socket,
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

            // TODO: check if the DHCP options contain the correct DHCP option aka make sure it is an DHCP Offer

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
            info!(target: "mydhcp::receive_offer", "- DHCP My IP address: {}", response.yiaddr);

            Ok(Self::ReceivedOffer {
                socket: Rc::clone(socket),
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
        shutdown_on_signal();
        if let DhcpClient::ReceivedOffer {
            ref socket,
            transaction_id,
            ip,
            server_ip,
            ref dhcp_options,
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
                socket: Rc::clone(socket),
                transaction_id,
                ip,
                server_ip,
                offered_dhcp_options: Rc::clone(dhcp_options),
            })
        } else {
            Err(DhcpClientError::DhcpInvalidState)
        }
    }

    fn receive_acknowledgement(self) -> Result<Self, DhcpClientError> {
        shutdown_on_signal();
        if let DhcpClient::Requesting {
            ref socket,
            transaction_id,
            ip,
            server_ip,
            ref offered_dhcp_options,
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

            // TODO: check if the DHCP options contain the correct DHCP option aka make sure it is an DHCP Offer

            info!(target: "mydhcp::receive_acknowledgement", "- Parsing DHCP options from the acknowledgment");
            let dhcp_options = DhcpOption::parse_dhcp_options(&acknowledgement.dhcp_options)
                .ok_or(DhcpClientError::DhcpOptionParsingError)?;

            info!(target: "mydhcp::receive_acknowledgement", "- Analyzing differences DHCP options from the offer and acknowledgment");
            let differences = compare_dhcp_options(&dhcp_options, &offered_dhcp_options);
            println!(
                "The following options were added or changed from the offer to the acknowledgment:"
            );
            for diff in differences.iter() {
                println!("{:?} -> {:?}", diff.0, diff.1);
            }

            let acknowledged_options = combine_dhcp_options(&dhcp_options, &offered_dhcp_options);

            Ok(DhcpClient::ReceivedAcknowledgment {
                socket: Rc::clone(socket),
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
        shutdown_on_signal();
        if let DhcpClient::ReceivedAcknowledgment {
            ref socket,
            transaction_id,
            ip,
            server_ip,
            ref acknowledged_options,
        } = self
        {
            info!(target: "mydhcp::activate", "Activating the DHCP Client with the received configuration");

            if server_ip == Ipv4Addr::BROADCAST {
                let server_ip = match (*acknowledged_options)
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
            }

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

            let lease_time = match acknowledged_options
                .iter()
                .find(|x| matches!(x, DhcpOption::IpAddressLeaseTime(_)))
                .ok_or(DhcpClientError::DhcpResponseOptionsMissingComponent(
                    "IP Address Lease Time".into(),
                ))? {
                DhcpOption::IpAddressLeaseTime(t) => *t,
                _ => panic!(
                    "this branch will of code should never execute since the find method already check for a ServerId and and the ok_or handles if nothing is returned so there is no need to put something here"
                ),
            };
            info!(target: "mydhcp::activate", "- Lease Time: {} seconds", lease_time);

            // Extract T1 and T2 timers from acknowledged_options, with defaults and warnings
            let t1 = match acknowledged_options
                .iter()
                .find(|x| matches!(x, DhcpOption::RenewalTime(_)))
            {
                Some(DhcpOption::RenewalTime(val)) => {
                    info!(target: "mydhcp::activate", "- Renewal (T1) Time: {} seconds", val);
                    *val
                }
                _ => {
                    warn!(
                        "T1 (Renewal Time) not provided by server, using default (50% of lease time)"
                    );
                    lease_time / 2
                }
            };

            let t2 = match acknowledged_options
                .iter()
                .find(|x| matches!(x, DhcpOption::RebindingTime(_)))
            {
                Some(DhcpOption::RebindingTime(val)) => {
                    info!(target: "mydhcp::activate", "- Rebinding (T2) Time: {} seconds", val);
                    *val
                }
                _ => {
                    warn!(
                        "T2 (Rebinding Time) not provided by server, using default (87.5% of lease time)"
                    );
                    (lease_time as f64 * 0.875) as u32
                }
            };

            let lease_time = std::time::Duration::from_secs(lease_time as u64);
            let t1 = std::time::Duration::from_secs(t1 as u64);
            let t2 = std::time::Duration::from_secs(t2 as u64);
            let now = std::time::Instant::now();
            let renewal_deadline = now + t1;
            let rebinding_deadline = now + t2;
            let expiration_deadline = now + lease_time;

            info!(target: "mydhcp::activate", "- Configuring the network with the received options");
            let netconfig = NetConfigManager::new()?;
            netconfig.set_ip(&socket.interface, ip)?;
            netconfig.set_mask(&socket.interface, mask)?;
            netconfig.set_gateway(
                &socket.interface,
                gateways
                    .get(0)
                    .ok_or(DhcpClientError::GatewayListEmpty)?
                    .clone(),
            )?;
            netconfig.set_dns(&dns_servers)?;
            netconfig.enable(&socket.interface)?;

            Ok(DhcpClient::Active {
                socket: Rc::clone(socket),
                transaction_id,
                ip,
                server_ip,
                acknowledged_options: Rc::clone(acknowledged_options),
                renewal_deadline,
                rebinding_deadline,
                expiration_deadline,
            })
        } else {
            Err(DhcpClientError::DhcpInvalidState)
        }
    }

    fn keep_track(self) -> Option<Self> {
        if let DhcpClient::Active {
            ref socket,
            transaction_id,
            ip,
            server_ip,
            ref acknowledged_options,
            renewal_deadline,
            rebinding_deadline,
            expiration_deadline,
        } = self
        {
            wait_until_with_abort(renewal_deadline);
            info!(target: "mydhcp::keep_track", "Resending a unicast DHCP Request packet to renew the lease");

            let new_client = DhcpClient::ReceivedOffer {
                socket: Rc::clone(&socket),
                transaction_id,
                ip,
                server_ip,
                dhcp_options: Rc::clone(&acknowledged_options),
            }
            .retry_requesting();

            match new_client {
                Ok(new_client) => {
                    info!(target: "mydhcp::keep_track", "Lease renewed successfully.");
                    return Some(new_client);
                }
                Err(e) => {
                    warn!(target: "mydhcp::keep_track", "Failed to renew lease: {}", e);
                }
            }

            wait_until_with_abort(rebinding_deadline);
            info!(target: "mydhcp::keep_track", "Retring a broadcast DHCP Request packet to renew the lease");

            let new_client = DhcpClient::ReceivedOffer {
                socket: Rc::clone(&socket),
                transaction_id,
                ip,
                server_ip: Ipv4Addr::BROADCAST,
                dhcp_options: Rc::clone(&acknowledged_options),
            }
            .retry_requesting();

            match new_client {
                Ok(new_client) => {
                    info!(target: "mydhcp::keep_track", "Lease renewed successfully.");
                    return Some(new_client);
                }
                Err(e) => {
                    warn!(target: "mydhcp::keep_track", "Failed to renew lease: {}", e);
                }
            }

            wait_until_with_abort(expiration_deadline);
            error!(target: "mydhcp::keep_track", "Lease expired, client is no longer active.");

            let netconfig = NetConfigManager::new().unwrap_or_else(|err| {
                error!("FATAL: failed to create NetConfigManager: {}", err);
                std::process::exit(1);
            });

            info!(target: "mydhcp::keep_track", "Cleaning up network configuration for interface '{}'", socket.interface);
            netconfig.cleanup(&socket.interface).unwrap_or_else(|err| {
                error!(
                    "FATAL: failed to clean up interface '{}': {}",
                    socket.interface, err
                );
                std::process::exit(1);
            });

            None
        } else {
            error!(target: "mydhcp::keep_track", "Client is not in an active state, cannot keep track of lease.");
            None
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
            let dhcp_payload: Option<DhcpPayload> =
                unsafe { DhcpPayload::from_sliced_packet(packet) };
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

impl Drop for DhcpClient {
    fn drop(&mut self) {
        if let DhcpClient::Active {
            socket,
            ip,
            server_ip,
            transaction_id,
            ..
        } = self
        { 
            // Full cleanup: reset IP, mask, gateway, DNS, and disable interface
            if let Ok(netconfig) = NetConfigManager::new() {
                if let Err(e) = netconfig.cleanup(&socket.interface) {
                    error!(
                        "Failed to clean up network configuration for interface '{}' during drop: {}",
                        socket.interface, e
                    );
                } else {
                    info!(
                        "Cleaned up network configuration for interface '{}' during drop.",
                        socket.interface
                    );
                }
            }

            let packet_builder = PacketBuilder::ethernet2(
                socket.interface_mac_address,
                [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            )
            .ipv4(ip.octets(), server_ip.octets(), 10)
            .udp(68, 67);

            let dhcp_payload =
                DhcpPayload::release(&socket.interface, *transaction_id, *ip, *server_ip);
            let raw_payload = dhcp_payload.to_bytes();
            
            let mut raw_packet = Vec::<u8>::with_capacity(packet_builder.size(raw_payload.len()));
            packet_builder.write(&mut raw_packet, &raw_payload).unwrap_or_else(|err| {
                error!("Failed to write DHCP Release packet: {}", err);
                std::process::exit(1);
            });

            socket.send_to(&raw_packet, &[0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8]).unwrap_or_else(|err| {
                error!("Failed to send DHCP Release packet: {}", err);
                std::process::exit(1);
            });
        }
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

fn wait_until_with_abort(deadline: std::time::Instant) {
    use std::time::*;

    const POLL_INTERVAL: Duration = Duration::from_secs(1);

    while Instant::now() < deadline {
        shutdown_on_signal();
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn shutdown_on_signal() {
    if SHOULD_SHUTDOWN.load(Ordering::SeqCst) {
        info!("Shutdown signal received, exiting gracefully.");
        std::process::exit(0);
    }
}
