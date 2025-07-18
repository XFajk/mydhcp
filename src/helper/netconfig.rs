//! Network Configuration Module
//!
//! Provides the `NetConfigManager` struct which is responsible for applying
//! and cleaning up network settings returned by a DHCP server.
//!
//! These settings include:
//! - IP address and subnet mask
//! - Default gateway
//! - DNS servers
//!
//! NOTE: This implementation currently shells out to `ip` and modifies `/etc/resolv.conf`.
//! Future versions should replace this with native Netlink via the `neli` crate.

use log::{error, info};
use std::{io::Write, net::Ipv4Addr, process::Command, rc::Rc};

/// Manages network configuration for a specific interface.
///
/// Handles setting and removing:
/// - IP address and subnet mask
/// - Default gateway
/// - DNS servers
///
/// Also automatically performs cleanup on drop.
#[derive(Debug)]
pub struct NetConfigManager {
    interface_name: Rc<str>,
    ip: Option<Ipv4Addr>,
    mask: Option<Ipv4Addr>,
    gateway: Option<Ipv4Addr>,
}

impl NetConfigManager {
    /// Creates a new `NetConfigManager` for the specified network interface.
    ///
    /// # Arguments
    ///
    /// * `interface_name` - The name of the interface to manage.
    ///
    /// # Returns
    ///
    /// A `NetConfigManager` with no IP/gateway/mask configured yet.
    pub fn new(interface_name: &Rc<str>) -> std::io::Result<Self> {
        Ok(NetConfigManager {
            interface_name: Rc::clone(interface_name),
            ip: None,
            mask: None,
            gateway: None,
        })
    }

    /// Sets the IP address and subnet mask on the managed interface.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to assign.
    /// * `mask` - The subnet mask as an `Ipv4Addr`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `ip addr add` command fails.
    ///
    /// # Panics
    ///
    /// This function does not panic.
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

    /// Adds a default route to the specified gateway for the interface.
    ///
    /// # Arguments
    ///
    /// * `gateway` - The IP address of the default gateway.
    ///
    /// # Errors
    ///
    /// Returns an error if the `ip route add` command fails.
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

    /// Writes DNS server addresses to `/etc/resolv.conf`.
    ///
    /// Only the first 3 addresses will be written.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to `/etc/resolv.conf` fails.
    pub fn set_dns(&self, dns_servers: &[Ipv4Addr]) -> std::io::Result<()> {
        info!(target: "mydhcp::netconfig::set_dns", "Setting DNS servers {:?} in the /etc/resolv.conf", dns_servers);
        let mut dns_file = std::fs::File::create("/etc/resolv.conf")?;

        let length = 3.min(dns_servers.len());

        for addr in dns_servers[..length].iter() {
            dns_file.write_all(format!("nameserver {}\n", addr).as_bytes())?;
        }

        Ok(())
    }

    /// Removes IP, gateway, and DNS configuration previously applied by the manager.
    ///
    /// Flushes routes and addresses using `ip route flush` and `ip addr flush`.
    ///
    /// # Errors
    ///
    /// Returns an error if flushing commands or file writes fail.
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
    /// Automatically calls `cleanup()` when the manager is dropped.
    ///
    /// Logs an error if cleanup fails.
    fn drop(&mut self) {
        if let Err(e) = self.cleanup() {
            error!(
                "Failed to clean up network configuration for interface '{}': {}",
                self.interface_name, e
            );
        }
    }
}
