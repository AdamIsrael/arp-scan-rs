use ansi_term::Color::{Green, Red};
use ipnetwork::{IpNetwork, NetworkSize};
use pnet_datalink::NetworkInterface;

/**
 * Prints on stdout a list of all available network interfaces with some
 * technical details. The goal is to present the most useful technical details
 * to pick the right network interface for scans.
 */
pub fn show_interfaces(interfaces: &[NetworkInterface]) {

    let mut interface_count = 0;
    let mut ready_count = 0;

    println!();
    for interface in interfaces.iter() {

        let up_text = match interface.is_up() {
            true => format!("{} UP", Green.paint("✔")),
            false => format!("{} DOWN", Red.paint("✖"))
        };
        let mac_text = match interface.mac {
            Some(mac_address) => format!("{}", mac_address),
            None => "No MAC address".to_string()
        };
        let first_ip = match interface.ips.get(0) {
            Some(ip_address) => format!("{}", ip_address),
            None => "".to_string()
        };

        println!("{: <20} {: <18} {: <20} {}", interface.name, up_text, mac_text, first_ip);

        interface_count += 1;
        if interface.is_up() && !interface.is_loopback() && !interface.ips.is_empty() {
            ready_count += 1;
        }
    }

    println!();
    println!("Found {} network interfaces, {} seems ready for ARP scans", interface_count, ready_count);
    if let Some(default_interface) = select_default_interface(interfaces) {
        println!("Default network interface will be {}", default_interface.name);
    }
    println!();
}

pub fn print_ascii_packet() {

    println!();
    println!(" 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 ");
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
    println!("|         Hardware type         |        Protocol type          |");
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|");
    println!("|         Hlen  | Plen          |          Operation            |");
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
    println!("|                          Sender HA                            |");
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
    println!("|             Sender HA         |      Sender IP                |");
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|");
    println!("|             Sender IP         |      Target HA                |");
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|");
    println!("|                          Target HA                            |");
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
    println!("|                          Target IP                            |");
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
    println!();
    println!(" - Hardware type (2 bytes), use --hw-type option to change");
    println!(" - Protocol type (2 bytes), use --proto-type option to change");
    println!();
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
    }
    else {
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
