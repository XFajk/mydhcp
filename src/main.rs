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
    time::Duration,
};

use dhcp_help::*;
use socket_help::RawSocket;

use crate::netconfig_help::NetConfigManager;

static SHOULD_SHUTDOWN: AtomicBool = AtomicBool::new(false);

fn main() {
    env_logger::init();

    if let Err(e) = ctrlc::set_handler(|| {
        info!("SIGINT received! Setting shutdown flag. The process will shutdown gracefully soon");
        SHOULD_SHUTDOWN.store(true, Ordering::SeqCst);
    }) {
        error!("Failed to set Ctrl-C handler: {}", e);
        panic!();
    }

    #[cfg(not(debug_assertions))]
    {
        std::panic::set_hook(Box::new(|_| {
            eprintln!("process panicked");
        }));

        unsafe {
            std::env::remove_var("RUST_BACKTRACE");
        }
    }

    let args: Vec<String> = args().collect();
    while !SHOULD_SHUTDOWN.load(Ordering::SeqCst) {
        let client = DhcpClient::establish_dhcp_connection(&args);

        let mut client = match client {
            Ok(client) => client,
            Err(DhcpClientError::ShutdownSignalReceived) => {
                println!("{}", DhcpClientError::ShutdownSignalReceived);
                return;
            }
            Err(e) => {
                error!("Failed to establish DHCP connection: {}", e);
                if let Err(e) = shutdown_on_signal() {
                    println!("{}", e);
                    return;
                }
                continue; // Retry on error
            }
        };

        info!("DHCP connection established successfully.");
        println!("{:#?}", client);

        while !SHOULD_SHUTDOWN.load(Ordering::SeqCst) {
            let possibly_new_client = client.keep_track();
            match possibly_new_client {
                Ok(new_client) => {
                    client = new_client;
                    info!("DHCP lease renewed successfully.");
                }
                Err(DhcpClientError::ShutdownSignalReceived) => {
                    println!("{}", DhcpClientError::ShutdownSignalReceived);
                    return;
                }
                Err(_) => {
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
        dhcp_options: DhcpOptions,
    },
    Requesting {
        socket: Rc<RawSocket>,
        transaction_id: u32,
        ip: Ipv4Addr,
        server_ip: Ipv4Addr,
        offered_dhcp_options: DhcpOptions,
    },
    ReceivedAcknowledgment {
        socket: Rc<RawSocket>,
        transaction_id: u32,
        ip: Ipv4Addr,
        server_ip: Ipv4Addr,
        acknowledged_options: DhcpOptions,
    },
    Active {
        socket: Rc<RawSocket>,
        transaction_id: u32,
        ip: Ipv4Addr,
        server_ip: Ipv4Addr,
        net_config: NetConfigManager,
        acknowledged_options: DhcpOptions,
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
        shutdown_on_signal()?;
        if let Self::Disconnected = self {
            info!(target: "mydhcp::connect", "Setting UP the DHCP Client");

            let interface_name = args
                .get(1)
                .ok_or(error::DhcpClientError::MissingInterface)
                .unwrap_or_else(|err| {
                    error!("FATAL: {}", err);
                    panic!();
                });

            info!(target: "mydhcp::connect", "- Creating a Socket for DHCP comunication on interface: {}", interface_name);
            let socket = Rc::new(RawSocket::bind(
                interface_name,
                Some(Duration::from_secs(1)),
            )?);
            socket.set_filter_command("udp port 68 or udp port 67")?;

            Ok(Self::Connected { socket })
        } else {
            Err(DhcpClientError::DhcpInvalidState)
        }
    }

    fn discover(self) -> Result<Self, error::DhcpClientError> {
        shutdown_on_signal()?;
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
        shutdown_on_signal()?;
        if let Self::Discovering {
            ref socket,
            transaction_id,
        } = self
        {
            info!(target: "mydhcp::receive_offer", "Waiting for DHCP Offer packet");
            let response = Self::get_dhcp_response(
                &socket,
                transaction_id,
                DhcpMessage::Offer,
                std::time::Duration::from_secs(10),
            )?;

            info!(target: "mydhcp::receive_offer", "- Received DHCP Offer packet");

            info!(target: "mydhcp::receive_offer", "- Parsing DHCP options from the response");
            let dhcp_options = DhcpOptions::parse_dhcp_options(&response.dhcp_options)
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
        shutdown_on_signal()?;
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
                offered_dhcp_options: dhcp_options.clone(),
            })
        } else {
            Err(DhcpClientError::DhcpInvalidState)
        }
    }

    fn receive_acknowledgement(self) -> Result<Self, DhcpClientError> {
        shutdown_on_signal()?;
        if let DhcpClient::Requesting {
            ref socket,
            transaction_id,
            ip,
            server_ip,
            ref offered_dhcp_options,
        } = self
        {
            info!(target: "mydhcp::receive_acknowledgement", "Waiting for DHCP Acknowledgment packet");
            let acknowledgement = Self::get_dhcp_response(
                &socket,
                transaction_id,
                DhcpMessage::Acknowledge,
                std::time::Duration::from_secs(10),
            )?;

            info!(target: "mydhcp::receive_acknowledgement", "- Received DHCP Acknowledgment packet");

            info!(target: "mydhcp::receive_acknowledgement", "- Parsing DHCP options from the acknowledgment");
            let dhcp_options = DhcpOptions::parse_dhcp_options(&acknowledgement.dhcp_options)
                .ok_or(DhcpClientError::DhcpOptionParsingError)?;

            info!(target: "mydhcp::receive_acknowledgement", "- Analyzing differences DHCP options from the offer and acknowledgment");
            let differences = DhcpOptions::compare(&dhcp_options, &offered_dhcp_options);
            println!(
                "The following options were added or changed from the offer to the acknowledgment:"
            );
            for diff in differences.iter() {
                println!("{:?} -> {:?}", diff.0, diff.1);
            }

            let acknowledged_options = DhcpOptions::combine(&dhcp_options, &offered_dhcp_options);

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
        shutdown_on_signal()?;
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
            {
                Some(DhcpOption::SubnetMask(mask)) => Some(*mask),
                None => None,
                _ => panic!(
                    "this branch will of code should never execute since the find method already check for a ServerId and and the ok_or handles if nothing is returned so there is no need to put something here"
                ),
            };
            if let Some(mask) = mask {
                info!(target: "mydhcp::activate", "- Subnet Mask: {}", mask);
            } else {
                warn!(target: "mydhcp::activate", "- Missing a Subnet Mask");
            }

            let dns_servers = match acknowledged_options
                .iter()
                .find(|x| matches!(x, DhcpOption::DomainNameServer(_)))
            {
                Some(DhcpOption::DomainNameServer(servers)) => Some(Rc::clone(servers)),
                None => None,
                _ => panic!(
                    "this branch will of code should never execute since the find method already check for a ServerId and and the ok_or handles if nothing is returned so there is no need to put something here"
                ),
            };
            if let Some(dns_servers) = &dns_servers {
                info!(target: "mydhcp::activate", "- DNS Servers: {:?}", dns_servers);
            } else {
                warn!(target: "mydhcp::activate", "- Missing DNS Servers");
            }

            let gateways = match acknowledged_options
                .iter()
                .find(|x| matches!(x, DhcpOption::Gateway(_)))
            {
                Some(DhcpOption::Gateway(gates)) => Some(Rc::clone(gates)),
                None => None,
                _ => panic!(
                    "this branch will of code should never execute since the find method already check for a ServerId and and the ok_or handles if nothing is returned so there is no need to put something here"
                ),
            };
            if let Some(gateways) = &gateways {
                info!(target: "mydhcp::activate", "- Gateways: {:?}", gateways);
            } else {
                warn!(target: "mydhcp::activate", "- Missing Gateways");
            }

            let lease_time = match acknowledged_options
                .iter()
                .find(|x| matches!(x, DhcpOption::IpAddressLeaseTime(_)))
            {
                Some(DhcpOption::IpAddressLeaseTime(t)) => *t,
                None => 500,
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
                    warn!(target: "mydhcp::activate", "- T1 (Renewal Time) not provided by server, using default (50% of lease time)");
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
                    warn!(target: "mydhcp::activate", "- T2 (Rebinding Time) not provided by server, using default (87.5% of lease time)");
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
            let mut net_config = NetConfigManager::new(&socket.interface)?;
            net_config.set_ip_and_mask(ip, mask.unwrap_or(Ipv4Addr::UNSPECIFIED))?;

            if let Some(gateways) = gateways {
                net_config.set_gateway(
                    gateways
                        .first()
                        .ok_or(DhcpClientError::GatewayListEmpty)?
                        .clone(),
                )?;
            }
            if let Some(dns_servers) = dns_servers {
                net_config.set_dns(&dns_servers)?;
            }

            Ok(DhcpClient::Active {
                socket: Rc::clone(socket),
                transaction_id,
                ip,
                server_ip,
                net_config,
                acknowledged_options: acknowledged_options.clone(),
                renewal_deadline,
                rebinding_deadline,
                expiration_deadline,
            })
        } else {
            Err(DhcpClientError::DhcpInvalidState)
        }
    }

    fn keep_track(self) -> Result<Self, DhcpClientError> {
        use std::mem::ManuallyDrop;
        use std::ptr::drop_in_place;

        let mut manual_self = ManuallyDrop::new(self);
        if let DhcpClient::Active {
            ref mut socket,
            transaction_id,
            ip,
            server_ip,
            ref mut net_config,
            ref mut acknowledged_options,
            renewal_deadline,
            rebinding_deadline,
            expiration_deadline,
        } = *manual_self
        {
            let shutdown_result = wait_until_with_abort(renewal_deadline);
            if let Err(e) = shutdown_result {
                unsafe {
                    ManuallyDrop::drop(&mut manual_self);
                }
                return Err(e);
            }

            info!(target: "mydhcp::keep_track", "Resending a unicast DHCP Request packet to renew the lease");

            let new_client = DhcpClient::ReceivedOffer {
                socket: Rc::clone(&socket),
                transaction_id,
                ip,
                server_ip,
                dhcp_options: acknowledged_options.clone(),
            }
            .retry_requesting();

            match new_client {
                Ok(new_client) => {
                    info!(target: "mydhcp::keep_track", "Lease renewed successfully.");
                    unsafe {
                        drop_in_place(socket);
                        drop_in_place(acknowledged_options);
                        drop_in_place(net_config);
                    }
                    return Ok(new_client);
                }
                Err(e) => {
                    warn!(target: "mydhcp::keep_track", "Failed to renew lease: {}", e);
                }
            }

            let shutdown_result = wait_until_with_abort(rebinding_deadline);
            if let Err(e) = shutdown_result {
                unsafe {
                    ManuallyDrop::drop(&mut manual_self);
                }
                return Err(e);
            }
            info!(target: "mydhcp::keep_track", "Retring a broadcast DHCP Request packet to renew the lease");

            let new_client = DhcpClient::ReceivedOffer {
                socket: Rc::clone(&socket),
                transaction_id,
                ip,
                server_ip: Ipv4Addr::BROADCAST,
                dhcp_options: acknowledged_options.clone(),
            }
            .retry_requesting();

            match new_client {
                Ok(new_client) => {
                    info!(target: "mydhcp::keep_track", "Lease renewed successfully.");
                    unsafe {
                        drop_in_place(socket);
                        drop_in_place(acknowledged_options);
                        drop_in_place(net_config);
                    }
                    return Ok(new_client);
                }
                Err(e) => {
                    warn!(target: "mydhcp::keep_track", "Failed to renew lease: {}", e);
                }
            }

            let shutdown_result = wait_until_with_abort(expiration_deadline);
            if let Err(e) = shutdown_result {
                unsafe {
                    ManuallyDrop::drop(&mut manual_self);
                }
                return Err(e);
            }
            error!(target: "mydhcp::keep_track", "Lease expired, client is no longer active.");
            unsafe {
                ManuallyDrop::drop(&mut manual_self);
            }

            Err(DhcpClientError::ExpiredLease)
        } else {
            error!(target: "mydhcp::keep_track", "Client is not in an active state, cannot keep track of lease.");
            Err(DhcpClientError::DhcpInvalidState)
        }
    }
}

impl DhcpClient {
    fn get_dhcp_response(
        socket: &RawSocket,
        transaction_id: u32,
        wanted_message_type: DhcpMessage,
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

            if let Some(dhcp_options) = DhcpOptions::parse_dhcp_options(&dhcp_payload.dhcp_options)
            {
                let message_type = dhcp_options.search_for_option(std::mem::discriminant(
                    &DhcpOption::DhcpMessageType(DhcpMessage::Unsupported),
                ))?;
                if let DhcpOption::DhcpMessageType(t) = message_type {
                    if t != wanted_message_type {
                        return None;
                    }
                }
            }

            Some(dhcp_payload)
        };

        let elapsed_time = std::time::Instant::now();

        while elapsed_time.elapsed() < time_out {
            shutdown_on_signal()?;
            let (data, _) = match socket.recv_from() {
                Ok(data_and_addr) => data_and_addr,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        continue;
                    }
                    return Err(e.into());
                }
            };
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
        #[cfg(debug_assertions)]
        info!(target: "mydhcp::drop", "Freeing the DHCP Client");

        if let DhcpClient::Active {
            socket,
            ip,
            server_ip,
            transaction_id,
            ..
        } = self
        {
            info!(target: "mydhcp::drop", "Sending DHCP Release packet");

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
            packet_builder
                .write(&mut raw_packet, &raw_payload)
                .unwrap_or_else(|err| {
                    error!("Failed to write DHCP Release packet: {}", err);
                    panic!()
                });

            socket
                .send_to(
                    &raw_packet,
                    &[0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8],
                )
                .unwrap_or_else(|err| {
                    error!("Failed to send DHCP Release packet: {}", err);
                    panic!();
                });
        }
    }
}

fn wait_until_with_abort(deadline: std::time::Instant) -> Result<(), DhcpClientError> {
    use std::time::*;

    const POLL_INTERVAL: Duration = Duration::from_secs(1);

    while Instant::now() < deadline {
        shutdown_on_signal()?;
        std::thread::sleep(POLL_INTERVAL);
    }

    Ok(())
}

fn shutdown_on_signal() -> Result<(), DhcpClientError> {
    if SHOULD_SHUTDOWN.load(Ordering::SeqCst) {
        Err(DhcpClientError::ShutdownSignalReceived)
    } else {
        Ok(())
    }
}
