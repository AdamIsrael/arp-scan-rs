use std::env;

use ipnetwork::{IpNetwork, NetworkSize};
use pnet_datalink::NetworkInterface;

/**
 * Based on the current UNIX environment, find if the process is run as root
 * user. This approach only supports Linux-like systems (Ubuntu, Fedore, MacOS, ...).
 */
pub fn is_root_user() -> bool {
    env::var("USER").unwrap_or_else(|_| String::from("")) == *"root"
}

/**
 * Computes multiple IPv4 networks total size, IPv6 network are not being
 * supported by this function.
 */
pub fn compute_network_size(ip_networks: &[&IpNetwork]) -> Result<u128, String> {
    let size = ip_networks.iter().fold(0u128, |total_size, ip_network| {
        let network_size: u128 = match ip_network.size() {
            NetworkSize::V4(ipv4_network_size) => ipv4_network_size.into(),
            NetworkSize::V6(_) => {
                0
                // return Err("IPv6 networks are not supported by the ARP protocol.");
            }
        };
        total_size + network_size
    });
    if size > 0 {
        Ok(size)
    } else {
        Err("IPv6 networks are not supported by the ARP protocol.".to_string())
    }
}

/**
 * Find a default network interface for scans, based on the operating system
 * priority and some interface technical details.
 */
pub fn select_default_interface(interfaces: &[NetworkInterface]) -> Option<NetworkInterface> {
    let default_interface = interfaces.iter().find(|interface| {
        if interface.mac.is_none() {
            return false;
        }

        if interface.ips.is_empty() || !interface.is_up() || interface.is_loopback() {
            return false;
        }

        let potential_ipv4 = interface.ips.iter().find(|ip| ip.is_ipv4());
        if potential_ipv4.is_none() {
            return false;
        }

        true
    });

    default_interface.cloned()
}
