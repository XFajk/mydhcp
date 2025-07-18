use log::{error, info};
use std::{io::Write, net::Ipv4Addr, process::Command, rc::Rc};

/// Manages network configuration using a netlink socket.
/// TODO: this method has to use netlink in future this shell out solution is only temporary
#[derive(Debug)]
pub struct NetConfigManager {
    interface_name: Rc<str>,
    ip: Option<Ipv4Addr>,
    mask: Option<Ipv4Addr>,
    gateway: Option<Ipv4Addr>,
}

impl NetConfigManager {
    /// Creates a new NetConfigManager by opening a netlink socket.
    pub fn new(interface_name: &Rc<str>) -> std::io::Result<Self> {
        Ok(NetConfigManager {
            interface_name: Rc::clone(interface_name),
            ip: None,
            mask: None,
            gateway: None,
        })
    }

    pub fn set_ip_and_mask(&mut self, ip: Ipv4Addr, mask: Ipv4Addr) -> std::io::Result<()> {
        info!(target: "mydhcp::netconfig::set_ip", "-- Setting IP address {}/{} for interface {}", ip,  mask.to_bits().count_ones(), self.interface_name);
        // TODO: Replace this logic with neli crate for netlink functionlaity
        let _ = Command::new("ip")
            .args([
                "addr",
                "add",
                &format!("{}/{}", ip, mask.to_bits().count_ones()),
                "dev",
                self.interface_name.as_ref(),
            ])
            .output()?;

        self.ip = Some(ip);
        self.mask = Some(mask);
        Ok(())
    }

    pub fn set_gateway(&mut self, gateway: Ipv4Addr) -> std::io::Result<()> {
        info!(target: "mydhcp::netconfig::set_gateway", "-- Setting gateway {} for interface {}", gateway, self.interface_name);

        // TODO: Replace this logic with neli crate for netlink functionlaity
        let _ = Command::new("ip")
            .args([
                "route",
                "add",
                "default",
                "via",
                &gateway.to_string(),
                "dev",
                self.interface_name.as_ref(),
            ])
            .output()?;

        self.gateway = Some(gateway);
        Ok(())
    }

    pub fn set_dns(&self, dns_servers: &[Ipv4Addr]) -> std::io::Result<()> {
        info!(target: "mydhcp::netconfig::set_dns", "Setting DNS servers {:?} in the /etc/resolv.conf", dns_servers);
        let mut dns_file = std::fs::File::create("/etc/resolv.conf")?;

        let length = 3.min(dns_servers.len());

        for addr in dns_servers[..length].iter() {
            dns_file.write_all(format!("nameserver {}\n", addr).as_bytes())?;
        }

        Ok(())
    }

    /// Cleans up network configuration by resetting IP, netmask, gateway, and DNS.
    pub fn cleanup(&mut self) -> std::io::Result<()> {
        info!(target: "mydhcp::netconfig::cleanup", "-- Cleaning up network configuration for interface {}", self.interface_name);

        let _ = std::fs::File::create("/etc/resolv.conf")?;

        if let None = self.gateway {
            info!(target: "mydhcp::netconfig::cleanup", "- No gateway set, skipping gateway removal");
            return Ok(());
        }
        // TODO: Replace this logic with neli crate for netlink functionlaity
        let _ = Command::new("ip")
            .args(["route", "flush", "dev", self.interface_name.as_ref()])
            .output()?;

        self.gateway = None;

        if self.ip.is_none() && self.mask.is_none()
        {
            info!(target: "mydhcp::netconfig::cleanup", "- No ip and mask set, skipping their removal");
            return Ok(());
        }

        // TODO: Replace this logic with neli crate for netlink functionlaity
        let _ = Command::new("ip")
            .args(["addr", "flush", "dev", self.interface_name.as_ref()])
            .output()?;

        self.ip = None;
        self.mask = None;

        Ok(())
    }
}

impl Drop for NetConfigManager {
    fn drop(&mut self) {
        if let Err(e) = self.cleanup() {
            error!(
                "Failed to clean up network configuration for interface '{}': {}",
                self.interface_name, e
            );
        }
    }
}
