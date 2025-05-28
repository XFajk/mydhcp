use etherparse::{SlicedPacket, TransportSlice};
use mac_address::mac_address_by_name;
use std::rc::Rc;

#[derive(Debug, Clone)]
pub struct DhcpOption {
    option: u8,
    value: Vec<u8>,
}

impl DhcpOption {
    pub fn parse_dhcp_options(options: &[u8]) -> Option<Rc<[Self]>> {
        let mut result = Vec::<Self>::new();

        let mut i = 0;
        while i < options.len() {
            let option = u8::from_be(*options.get(i)?);
            if option == 0xff {
                break;
            }

            let option_len: u8 = u8::from_be(*options.get(i + 1).unwrap());
            let mut value = Vec::<u8>::with_capacity(option_len as usize);

            value.extend_from_slice(options.get(i + 2..i + 2 + (option_len as usize))?);

            result.push(Self { option, value });

            i += (2 + option_len) as usize;
        }

        Some(result.into())
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
    ciaddr: u32, // client address
    yiaddr: u32, // your address
    siaddr: u32, // server address
    giaddr: u32, // gateway address
    chaddr: [u8; 16],
    sname: [u8; 64],
    file: [u8; 128],
    magic_cookie: u32,
    pub dhcp_options: Vec<u8>,
}

impl DhcpPayload {
    pub fn discover(interface_name: &str, transaction_id: u32) -> Self {
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

        discover_payload
            .dhcp_options
            .extend_from_slice(&0x350101FF_u32.to_be_bytes());

        discover_payload
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

        data.extend_from_slice(&self.ciaddr.to_be_bytes());
        data.extend_from_slice(&self.yiaddr.to_be_bytes());
        data.extend_from_slice(&self.siaddr.to_be_bytes());
        data.extend_from_slice(&self.giaddr.to_be_bytes());
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
            ciaddr: u32::from_be_bytes(bytes.get(12..16)?.try_into().ok()?),
            yiaddr: u32::from_be_bytes(bytes.get(16..20)?.try_into().ok()?),
            siaddr: u32::from_be_bytes(bytes.get(20..24)?.try_into().ok()?),
            giaddr: u32::from_be_bytes(bytes.get(24..28)?.try_into().ok()?),
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
            ciaddr: 0,
            yiaddr: 0,
            siaddr: 0,
            giaddr: 0,
            chaddr: [0; 16],
            sname: [0; 64],
            file: [0; 128],
            magic_cookie: 0x63825363_u32,
            dhcp_options: Vec::new(),
        }
    }
}
