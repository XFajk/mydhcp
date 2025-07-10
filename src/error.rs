use std::rc::Rc;

use mac_address::MacAddressError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DhcpClientError {
    #[error("System IO Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Packet Capture Error: {0}")]
    PcapError(#[from] pcap::Error),
    #[error("Packet Parsing Error: {0}")]
    PacketParsingError(#[from] etherparse::err::packet::SliceError),
    #[error("Packet Building Error: {0}")]
    PacketBuildingError(#[from] etherparse::err::packet::BuildWriteError),
    #[error("Mac Address Error: {0}")]
    MacAddressError(#[from] MacAddressError),
    #[error("System Time Error: {0}")]
    TimeError(#[from] std::time::SystemTimeError),
    #[error("Missing interface name argument")]
    MissingInterface,
    #[error("Interface({0}) Missing mac address")]
    InterfaceMissingMacAddress(Rc<str>),
    #[error("Nothing Received in allowed time frame {0:?}")]
    TimedOut(std::time::Duration),
    #[error("Dhcp Options are incorrectly formatted")]
    DhcpOptionParsingError,
    #[error("The DHCP client is in incorrect state for this operation")]
    DhcpInvalidState,
    #[error("The DHCP response sent by the server is missing {0}")]
    DhcpResponseOptionsMissingComponent(Box<str>),
    #[error("gateway list is empty")]
    GatewayListEmpty,
    #[error("Dhcp response options were rejected by the client")]
    DhcpResponseOptionsRejected,
}
