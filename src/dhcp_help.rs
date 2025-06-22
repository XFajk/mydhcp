use etherparse::{SlicedPacket, TransportSlice};
use mac_address::mac_address_by_name;
use std::{net::Ipv4Addr, rc::Rc};

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

#[derive(Debug, Clone, PartialEq)]
pub enum DhcpOption {
    SubnetMask(Ipv4Addr),                // 1
    Gateway(Rc<[Ipv4Addr]>),             // 3
    DomainNameServer(Rc<[Ipv4Addr]>),    // 6
    HostName(Rc<str>),                   // 12
    DomainName(Rc<str>),                 // 15
    BroadcastAddress(Ipv4Addr),          // 28
    IpAddressRequest(Ipv4Addr),          // 50
    IpAddressLeaseTime(u32),             // 51
    DhcpMessageType(DhcpMessage),        // 53
    ServerId(Ipv4Addr),                  // 54
    ParameterRequestList(Rc<[u8]>),      // 55
    RenewalTime(u32),                    // 58
    RebindingTime(u32),                  // 59
    End,                                 // 255
    Pad,                                 // 0
    UnsupportedOption(u8, Rc<[u8]>),     // any other
}

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
            _ => Self::UnsupportedOption(code, data.into()),
        }
    }
}

impl DhcpOption {
    pub fn parse_dhcp_options(options: &[u8]) -> Option<Rc<[Self]>> {
        let mut result = Vec::<Self>::new();

        let mut i = 0;
        while i < options.len() {
            let option = u8::from_be(*options.get(i)?);
            if option == 0xff {
                result.push(DhcpOption::End);
                break;
            }

            let option_len: u8 = u8::from_be(*options.get(i + 1)?);
            let mut value = Vec::<u8>::with_capacity(option_len as usize);

            value.extend_from_slice(options.get(i + 2..i + 2 + (option_len as usize))?);

            result.push((option, value).into());

            i += (2 + option_len) as usize;
        }

        Some(result.into())
    }

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
            }
        }
        // Ensure the options end with End (255)
        if !bytes.is_empty() && *bytes.last().unwrap() != 255 {
            bytes.push(255);
        }
        bytes.into()
    }
}

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
