//! DHCP Helper Module
//!
//! This module provides structured abstractions over raw DHCP packets,
//! allowing for parsing, composing, comparing, and serializing DHCP data.
//!
//! It defines:
//! - `DhcpMessage`: Enumeration of message types
//! - `DhcpOption`: Strongly typed variants for supported DHCP options
//! - `DhcpOptions`: Utility wrapper for searching, comparing, and combining options
//! - `DhcpPayload`: A full DHCP packet (header + options), with support for discovery, request, release and deserialization
//!
//! Used throughout the DHCP client to construct, parse, and reason about protocol data.

use etherparse::{SlicedPacket, TransportSlice};
use mac_address::mac_address_by_name;
use std::{
    mem::{Discriminant, discriminant},
    net::Ipv4Addr,
    ops::{Deref, DerefMut},
    rc::Rc,
};

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DhcpMessage {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Acknowledge = 5,
    UnAcknowledge = 6,
    Release = 7,
    Inform = 8,
    Unsupported = 0,
}

/// Represents a DHCP option with a strongly-typed variant.
///
/// This enum abstracts over raw DHCP option bytes, converting them into
/// safe, structured Rust values that can be matched and manipulated.
///
/// Options are parsed from `(u8, Vec<u8>)` tuples and support conversion
/// back into byte arrays with [`DhcpOption::into_bytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpOption {
    SubnetMask(Ipv4Addr),             // 1
    Gateway(Rc<[Ipv4Addr]>),          // 3
    DomainNameServer(Rc<[Ipv4Addr]>), // 6
    HostName(Rc<str>),                // 12
    DomainName(Rc<str>),              // 15
    BroadcastAddress(Ipv4Addr),       // 28
    IpAddressRequest(Ipv4Addr),       // 50
    IpAddressLeaseTime(u32),          // 51
    DhcpMessageType(DhcpMessage),     // 53
    ServerId(Ipv4Addr),               // 54
    ParameterRequestList(Rc<[u8]>),   // 55
    RenewalTime(u32),                 // 58
    RebindingTime(u32),               // 59
    ClientId((u8, [u8; 6])),          // 61: 1 byte type, 6 bytes MAC address
    End,                              // 255
    Pad,                              // 0
    UnsupportedOption(u8, Rc<[u8]>),  // any other
}

/// Converts a raw DHCP option tuple `(code, data)` into a typed `DhcpOption` enum.
///
/// This parser handles known codes (1, 3, 6, 12, 15, 28, 50, etc.) and converts them
/// into structured variants. Unknown codes are stored in `UnsupportedOption`.
///
/// # Examples
///
/// ```
/// let option = DhcpOption::from((1, vec![255, 255, 255, 0]));
/// assert_eq!(option, DhcpOption::SubnetMask(Ipv4Address::new(255, 255, 255, 0)));
/// ```
impl From<(u8, Vec<u8>)> for DhcpOption {
    fn from(value: (u8, Vec<u8>)) -> Self {
        let (code, data) = value;
        match code {
            0 => Self::Pad,
            1 if data.len() == 4 => {
                Self::SubnetMask(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
            }
            3 if data.len() % 4 == 0 => {
                let addrs = data
                    .chunks(4)
                    .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
                    .collect::<Vec<_>>()
                    .into();
                Self::Gateway(addrs)
            }
            6 if data.len() % 4 == 0 => {
                let addrs = data
                    .chunks(4)
                    .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
                    .collect::<Vec<_>>()
                    .into();
                Self::DomainNameServer(addrs)
            }
            12 => Self::HostName(Rc::from(String::from_utf8_lossy(&data).into_owned())),
            15 => Self::DomainName(Rc::from(String::from_utf8_lossy(&data).into_owned())),
            28 if data.len() == 4 => {
                Self::BroadcastAddress(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
            }
            50 if data.len() == 4 => {
                Self::IpAddressRequest(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
            }
            51 if data.len() == 4 => {
                let secs = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                Self::IpAddressLeaseTime(secs)
            }
            53 if data.len() == 1 => {
                let msg = match data[0] {
                    1 => DhcpMessage::Discover,
                    2 => DhcpMessage::Offer,
                    3 => DhcpMessage::Request,
                    4 => DhcpMessage::Decline,
                    5 => DhcpMessage::Acknowledge,
                    6 => DhcpMessage::UnAcknowledge,
                    7 => DhcpMessage::Release,
                    8 => DhcpMessage::Inform,
                    _ => DhcpMessage::Unsupported,
                };
                Self::DhcpMessageType(msg)
            }
            54 if data.len() == 4 => {
                Self::ServerId(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
            }
            55 => Self::ParameterRequestList(data.into()),
            58 if data.len() == 4 => {
                let t = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                Self::RenewalTime(t)
            }
            59 if data.len() == 4 => {
                let t = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                Self::RebindingTime(t)
            }
            255 => Self::End,
            61 if data.len() == 7 => {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(&data[1..7]);
                Self::ClientId((data[0], mac))
            }
            _ => Self::UnsupportedOption(code, data.into()),
        }
    }
}

impl DhcpOption {
    /// Converts a slice of `DhcpOption`s into a serialized byte array.
    ///
    /// This is used to encode options when constructing DHCP packets.
    ///
    /// Ensures the resulting sequence ends with the `End (255)` option if not already present.
    pub fn into_bytes(options: &[Self]) -> Rc<[u8]> {
        let mut bytes = Vec::new();
        for option in options {
            match option {
                DhcpOption::Pad => bytes.push(0),
                DhcpOption::SubnetMask(addr) => {
                    bytes.push(1);
                    bytes.push(4);
                    bytes.extend_from_slice(&addr.octets());
                }
                DhcpOption::Gateway(addrs) => {
                    bytes.push(3);
                    bytes.push((addrs.len() * 4) as u8);
                    for addr in addrs.iter() {
                        bytes.extend_from_slice(&addr.octets());
                    }
                }
                DhcpOption::DomainNameServer(addrs) => {
                    bytes.push(6);
                    bytes.push((addrs.len() * 4) as u8);
                    for addr in addrs.iter() {
                        bytes.extend_from_slice(&addr.octets());
                    }
                }
                DhcpOption::HostName(name) => {
                    bytes.push(12);
                    bytes.push(name.len() as u8);
                    bytes.extend_from_slice(name.as_bytes());
                }
                DhcpOption::DomainName(name) => {
                    bytes.push(15);
                    bytes.push(name.len() as u8);
                    bytes.extend_from_slice(name.as_bytes());
                }
                DhcpOption::BroadcastAddress(addr) => {
                    bytes.push(28);
                    bytes.push(4);
                    bytes.extend_from_slice(&addr.octets());
                }
                DhcpOption::IpAddressRequest(addr) => {
                    bytes.push(50);
                    bytes.push(4);
                    bytes.extend_from_slice(&addr.octets());
                }
                DhcpOption::IpAddressLeaseTime(secs) => {
                    bytes.push(51);
                    bytes.push(4);
                    bytes.extend_from_slice(&secs.to_be_bytes());
                }
                DhcpOption::DhcpMessageType(msg) => {
                    bytes.push(53);
                    bytes.push(1);
                    bytes.push(*msg as u8);
                }
                DhcpOption::ServerId(id) => {
                    bytes.push(54);
                    bytes.push(4);
                    bytes.extend_from_slice(&id.octets());
                }
                DhcpOption::ParameterRequestList(list) => {
                    bytes.push(55);
                    bytes.push(list.len() as u8);
                    bytes.extend_from_slice(list);
                }
                DhcpOption::RenewalTime(t) => {
                    bytes.push(58);
                    bytes.push(4);
                    bytes.extend_from_slice(&t.to_be_bytes());
                }
                DhcpOption::RebindingTime(t) => {
                    bytes.push(59);
                    bytes.push(4);
                    bytes.extend_from_slice(&t.to_be_bytes());
                }
                DhcpOption::End => bytes.push(255),
                DhcpOption::UnsupportedOption(code, data) => {
                    bytes.push(*code);
                    bytes.push(data.len() as u8);
                    bytes.extend_from_slice(data);
                }
                DhcpOption::ClientId((t, mac)) => {
                    bytes.push(61);
                    bytes.push(7);
                    bytes.push(*t);
                    bytes.extend_from_slice(mac);
                }
            }
        }
        // Ensure the options end with End (255)
        if !bytes.is_empty() && *bytes.last().unwrap() != 255 {
            bytes.push(255);
        }
        bytes.into()
    }
}

/// A wrapper around a reference-counted slice of [`DhcpOption`] values.
///
/// Provides helper methods to:
/// - Parse options from raw bytes
/// - Search for an option by type
/// - Compare two option lists
/// - Combine new and old options
#[derive(Debug, Clone)]
pub struct DhcpOptions(Rc<[DhcpOption]>);

impl Deref for DhcpOptions {
    type Target = Rc<[DhcpOption]>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for DhcpOptions {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl DhcpOptions {
    /// Parses raw DHCP option bytes into a structured `DhcpOptions` wrapper.
    ///
    /// # Returns
    ///
    /// Returns `Some(DhcpOptions)` if parsing succeeds. Returns `None` if
    /// any offset/index is out of bounds or formatting is invalid.
    pub fn parse_dhcp_options(options: &[u8]) -> Option<Self> {
        let mut result = Vec::<DhcpOption>::new();

        let mut i = 0;
        while i < options.len() {
            let option = u8::from_be(*options.get(i)?);
            if option == 0xff {
                break;
            }

            let option_len: u8 = u8::from_be(*options.get(i + 1)?);
            let mut value = Vec::<u8>::with_capacity(option_len as usize);

            value.extend_from_slice(options.get(i + 2..i + 2 + (option_len as usize))?);

            result.push((option, value).into());

            i += (2 + option_len) as usize;
        }

        Some(DhcpOptions(result.into()))
    }

    /// Searches for a DHCP option by discriminant and returns a clone if found.
    ///
    /// Used to find a specific option like `DhcpMessageType` or `ServerId` in the list.
    pub fn search(&self, option_discriminant: Discriminant<DhcpOption>) -> Option<DhcpOption> {
        for o in self.iter() {
            if discriminant(o) == option_discriminant {
                return Some(o.clone());
            }
        }

        None
    }

    /// Compares two DHCP option lists and returns all differing or new options.
    ///
    /// Each entry in the result is a tuple:
    /// - `Some(&old)` if the option existed but changed
    /// - `None` if the option is entirely new
    ///
    /// Used to track configuration changes during renewal.
    pub fn compare<'a>(
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

    /// Combines new and old DHCP options by appending only non-duplicate entries from old.
    ///
    /// If a new option already includes a variant, it is not overridden.
    /// Preserves all options present in the newer set.
    pub fn combine(new_options: &[DhcpOption], old_options: &[DhcpOption]) -> Self {
        use std::mem::discriminant;

        let mut result: Vec<DhcpOption> = Vec::from(new_options);

        for old_o in old_options {
            let d = discriminant(old_o);
            if !result.iter().any(|o| discriminant(o) == d) {
                result.push(old_o.clone());
            }
        }

        DhcpOptions(result.into())
    }
}

/// A full DHCP packet structure containing both the fixed header and dynamic options.
///
/// Used to build and serialize DHCP packets for DISCOVER, REQUEST, and RELEASE messages.
///
/// The fields directly map to the DHCP packet format as described in RFC 2131.
///
/// Use `DhcpPayload::to_bytes` to serialize, and `DhcpPayload::from_bytes` to parse from a buffer.
#[derive(Clone, Debug)]
pub struct DhcpPayload {
    op: u8,
    htype: u8,
    hlen: u8,
    hops: u8,
    pub xid: u32,
    secs: u16,
    flags: u16,
    pub ciaddr: Ipv4Addr, // client address
    pub yiaddr: Ipv4Addr, // your address
    pub siaddr: Ipv4Addr, // server address
    pub giaddr: Ipv4Addr, // gateway address
    chaddr: [u8; 16],
    sname: [u8; 64],
    file: [u8; 128],
    magic_cookie: u32,
    pub dhcp_options: Vec<u8>,
}

impl DhcpPayload {
    /// Constructs a DHCP DISCOVER packet for the given interface and transaction ID.
    ///
    /// # Arguments
    ///
    /// * `interface_name` - Network interface to derive the MAC address from.
    /// * `transaction_id` - Unique identifier for the DHCP exchange.
    /// * `requested_ip` - Optional IP address the client wishes to request.
    ///
    /// # Returns
    ///
    /// A `DhcpPayload` representing the DISCOVER message.
    ///
    /// # Panics
    ///
    /// This function panics if the MAC address for the interface cannot be resolved
    /// (via `mac_address_by_name(...).unwrap().unwrap()`).
    /// 
    pub fn discover(
        interface_name: &str,
        transaction_id: u32,
        requested_ip: Option<Ipv4Addr>,
    ) -> Self {
        let mut discover_payload = Self {
            op: 1_u8,
            htype: 1_u8,
            hlen: 6_u8,
            xid: transaction_id,

            ..Default::default()
        };

        discover_payload.chaddr[0..6].copy_from_slice(
            &mac_address_by_name(interface_name)
                .unwrap()
                .unwrap()
                .bytes(),
        );

        let mut dhcp_options: Vec<DhcpOption> = Vec::new();
        dhcp_options.push(DhcpOption::DhcpMessageType(DhcpMessage::Discover));
        if let Some(ip) = requested_ip {
            dhcp_options.push(DhcpOption::IpAddressRequest(ip));
        }
        dhcp_options.push(DhcpOption::End);

        discover_payload
            .dhcp_options
            .extend_from_slice(&DhcpOption::into_bytes(&dhcp_options));

        discover_payload
    }

    /// Constructs a DHCP REQUEST packet for a previously offered IP.
    ///
    /// # Arguments
    ///
    /// * `interface_name` - Network interface used to get MAC address.
    /// * `transaction_id` - The same transaction ID from the DISCOVER phase.
    /// * `ip` - The offered IP address the client wants to request.
    /// * `server_ip` - The IP of the DHCP server to send the request to.
    ///
    /// # Returns
    ///
    /// A `DhcpPayload` representing the REQUEST message.
    ///
    /// # Panics
    ///
    /// Panics if the MAC address cannot be retrieved (via `.unwrap().unwrap()`).
    /// 
    pub fn request(
        interface_name: &str,
        transaction_id: u32,
        ip: Ipv4Addr,
        server_ip: Ipv4Addr,
    ) -> Self {
        let mut request_payload = Self {
            op: 1_u8,
            htype: 1_u8,
            hlen: 6_u8,
            xid: transaction_id,
            siaddr: server_ip,

            ..Default::default()
        };

        request_payload.chaddr[0..6].copy_from_slice(
            &mac_address_by_name(interface_name)
                .unwrap()
                .unwrap()
                .bytes(),
        );

        let mut dhcp_options: Vec<DhcpOption> = Vec::new();
        dhcp_options.push(DhcpOption::DhcpMessageType(DhcpMessage::Request));
        dhcp_options.push(DhcpOption::IpAddressRequest(ip));
        dhcp_options.push(DhcpOption::ServerId(server_ip));
        dhcp_options.push(DhcpOption::End);

        request_payload
            .dhcp_options
            .extend_from_slice(&DhcpOption::into_bytes(&dhcp_options));

        request_payload
    }

    /// Constructs a DHCP RELEASE packet to relinquish a leased IP.
    ///
    /// # Arguments
    ///
    /// * `interface_name` - Interface from which to get the MAC address.
    /// * `transaction_id` - Transaction ID used during the lease.
    /// * `ip` - The IP address to release.
    /// * `server_ip` - The DHCP server's IP address.
    ///
    /// # Returns
    ///
    /// A `DhcpPayload` representing the RELEASE message.
    ///
    /// # Panics
    ///
    /// Panics if the MAC address retrieval fails (`unwrap().unwrap()` on result of `mac_address_by_name`).
    /// 
    pub fn release(
        interface_name: &str,
        transaction_id: u32,
        ip: Ipv4Addr,
        server_ip: Ipv4Addr,
    ) -> Self {
        let mut release_payload = Self {
            op: 1_u8,
            htype: 1_u8,
            hlen: 6_u8,
            xid: transaction_id,
            ciaddr: ip,

            ..Default::default()
        };

        let my_mac = mac_address_by_name(interface_name)
            .unwrap()
            .unwrap()
            .bytes();

        release_payload.chaddr[0..6].copy_from_slice(&my_mac);

        let mut dhcp_options: Vec<DhcpOption> = Vec::new();
        dhcp_options.push(DhcpOption::DhcpMessageType(DhcpMessage::Release));
        dhcp_options.push(DhcpOption::ClientId((1, my_mac)));
        dhcp_options.push(DhcpOption::ServerId(server_ip));
        dhcp_options.push(DhcpOption::End);

        release_payload
            .dhcp_options
            .extend_from_slice(&DhcpOption::into_bytes(&dhcp_options));

        release_payload
    }

    /// Serializes the `DhcpPayload` into a byte array ready for transmission.
    ///
    /// Converts all header fields and DHCP options to network byte order.
    ///
    /// # Returns
    ///
    /// A boxed byte slice containing the full DHCP message.
    ///
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut data = Vec::<u8>::new();
        data.push(self.op.to_be());

        data.push(self.htype.to_be());
        data.push(self.hlen.to_be());
        data.push(self.hops.to_be());

        data.extend_from_slice(&self.xid.to_be_bytes());

        data.extend_from_slice(&self.secs.to_be_bytes());
        data.extend_from_slice(&self.flags.to_be_bytes());

        data.extend_from_slice(&self.ciaddr.to_bits().to_be_bytes());
        data.extend_from_slice(&self.yiaddr.to_bits().to_be_bytes());
        data.extend_from_slice(&self.siaddr.to_bits().to_be_bytes());
        data.extend_from_slice(&self.giaddr.to_bits().to_be_bytes());
        data.extend(self.chaddr.iter().map(|x| x.to_be()));

        data.extend(self.sname.iter().map(|x| x.to_be()));
        data.extend(self.file.iter().map(|x| x.to_be()));

        data.extend_from_slice(&self.magic_cookie.to_be_bytes());
        data.extend(self.dhcp_options.clone());

        data.into_boxed_slice()
    }

    /// Parses a byte slice into a `DhcpPayload`.
    ///
    /// # Safety
    ///
    /// This function is `unsafe` because it performs unchecked indexing and assumes
    /// the byte layout is correct and complete per RFC2131.
    ///
    /// # Returns
    ///
    /// `Some(DhcpPayload)` if parsing succeeds; otherwise `None`.
    /// 
    pub unsafe fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Some(Self {
            op: *bytes.get(0)?,
            htype: *bytes.get(1)?,
            hlen: *bytes.get(2)?,
            hops: *bytes.get(3)?,
            xid: u32::from_be_bytes(bytes.get(4..8)?.try_into().ok()?),
            secs: u16::from_be_bytes(bytes.get(8..10)?.try_into().ok()?),
            flags: u16::from_be_bytes(bytes.get(10..12)?.try_into().ok()?),
            ciaddr: u32::from_be_bytes(bytes.get(12..16)?.try_into().ok()?).into(),
            yiaddr: u32::from_be_bytes(bytes.get(16..20)?.try_into().ok()?).into(),
            siaddr: u32::from_be_bytes(bytes.get(20..24)?.try_into().ok()?).into(),
            giaddr: u32::from_be_bytes(bytes.get(24..28)?.try_into().ok()?).into(),
            chaddr: bytes.get(28..44)?.try_into().ok()?,
            sname: bytes.get(44..108)?.try_into().ok()?,
            file: bytes.get(108..236)?.try_into().ok()?,
            magic_cookie: u32::from_be_bytes(bytes.get(236..240)?.try_into().ok()?),
            dhcp_options: bytes.get(240..)?.try_into().ok()?,
        })
    }

    /// Attempts to parse a `DhcpPayload` from a sliced UDP packet.
    ///
    /// # Safety
    ///
    /// This function is `unsafe` because it forwards to `from_bytes`, which assumes
    /// the buffer layout matches the DHCP protocol.
    ///
    /// # Returns
    ///
    /// `Some(DhcpPayload)` if the transport layer is UDP and payload is well-formed.
    /// `None` if the slice is not UDP or the payload fails to parse.
    /// 
    pub unsafe fn from_sliced_packet(sliced: SlicedPacket<'_>) -> Option<Self> {
        if let Some(TransportSlice::Udp(udp_slice)) = sliced.transport {
            unsafe { Self::from_bytes(udp_slice.payload()) }
        } else {
            None
        }
    }
}

impl Default for DhcpPayload {
    fn default() -> Self {
        Self {
            op: 0,
            htype: 0,
            hlen: 0,
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::new(0, 0, 0, 0),
            yiaddr: Ipv4Addr::new(0, 0, 0, 0),
            siaddr: Ipv4Addr::new(0, 0, 0, 0),
            giaddr: Ipv4Addr::new(0, 0, 0, 0),
            chaddr: [0; 16],
            sname: [0; 64],
            file: [0; 128],
            magic_cookie: 0x63825363_u32,
            dhcp_options: Vec::new(),
        }
    }
}
