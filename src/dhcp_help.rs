use mac_address::mac_address_by_name;

#[repr(C, packed)]
pub struct DhcpPacket {
    op: u8,
    htype: u8,
    hlen: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: u16,
    ciaddr: u32, // client address
    yiaddr: u32, // your address
    siaddr: u32, // server address
    giaddr: u32, // gateway address
    chaddr: [u8; 16],
    sname: [u8; 64],
    file: [u8; 128],
    dhcp_area: [u8; 64], // vendor area
}

impl DhcpPacket {
    pub fn discover() -> Self {
        let mut packet = Self {
            op: 1_u8.to_be(),
            htype: 1_u8.to_be(),
            hlen: 6_u8.to_be(),
            xid: 0x4312FFFF_u32.to_be(),
            ..Default::default()
        };

        packet.chaddr[0..6]
            .copy_from_slice(&mac_address_by_name("wlp2s0").unwrap().unwrap().bytes());
        packet.dhcp_area[0..4].copy_from_slice(&0x63825363_u32.to_be_bytes());
        packet.dhcp_area[4] = 0x35_u8.to_be();
        packet.dhcp_area[5] = 0x01_u8.to_be();
        packet.dhcp_area[6] = 0x01_u8.to_be();
        packet.dhcp_area[7] = 0xFF;

        packet
    }
}

impl Default for DhcpPacket {
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
            dhcp_area: [0; 64],
        }
    }
}
