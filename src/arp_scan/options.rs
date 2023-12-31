use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use ipnetwork::IpNetwork;
use pnet::packet::arp::{ArpHardwareType, ArpOperation};
use pnet::packet::ethernet::EtherType;
use pnet_datalink::MacAddr;

pub const TIMEOUT_MS_FAST: u64 = 800;
pub const TIMEOUT_MS_DEFAULT: u64 = 2000;

pub const HOST_RETRY_DEFAULT: usize = 1;
pub const REQUEST_MS_INTERVAL: u64 = 10;

#[derive(Debug, PartialEq)]
pub enum ProfileType {
    Default,
    Fast,
    Stealth,
    Chaos,
}

#[derive(Debug)]
pub enum ScanTiming {
    Interval(u64),
    Bandwidth(u64),
}

#[derive(Debug)]
pub struct ScanOptions {
    pub profile: ProfileType,
    pub interface_name: Option<String>,
    pub network_range: Option<Vec<ipnetwork::IpNetwork>>,
    pub timeout_ms: u64,
    pub resolve_hostname: bool,
    pub source_ipv4: Option<Ipv4Addr>,
    pub source_mac: Option<MacAddr>,
    pub destination_mac: Option<MacAddr>,
    pub vlan_id: Option<u16>,
    pub retry_count: usize,
    pub scan_timing: ScanTiming,
    pub randomize_targets: bool,
    // pub output: OutputFormat,
    pub oui_file: String,
    pub hw_type: Option<ArpHardwareType>,
    pub hw_addr: Option<u8>,
    pub proto_type: Option<EtherType>,
    pub proto_addr: Option<u8>,
    pub arp_operation: Option<ArpOperation>,
    // pub packet_help: bool,
    pub bandwidth: Option<u64>,
    pub interval: Option<u64>,
}

impl ScanOptions {
    /**
     * Build a new 'ScanOptions' struct that will be used in the whole CLI such
     * as the network level, the display details and more. The scan options reflect
     * user requests for the CLI and should not be mutated.
     */
    pub fn new(
        profile: ProfileType,
        interface_name: Option<String>,
        network_range: Option<Vec<IpNetwork>>,
        timeout: Option<u64>,
        hostname_numeric: Option<bool>,
        source_ip: Option<String>,
        destination_mac: Option<MacAddr>,
        source_mac: Option<MacAddr>,
        vlan_id: Option<u16>,
        retries: Option<usize>,
        random: Option<bool>,
        oui: Option<String>,
        hw_type: Option<ArpHardwareType>,
        hw_addr: Option<u8>,
        proto_type: Option<EtherType>,
        proto_addr: Option<u8>,
        arp_operation: Option<ArpOperation>,
        bandwidth: Option<u64>,
        interval: Option<u64>,
    ) -> Result<Arc<Self>, String> {
        let mut timeout_ms = timeout.unwrap_or(TIMEOUT_MS_DEFAULT);
        if profile == ProfileType::Fast {
            timeout_ms = TIMEOUT_MS_FAST;
        }

        // Hostnames will not be resolved in numeric mode or stealth profile
        // let resolve_hostname = !matches.get_flag("numeric") && !matches!(profile, ProfileType::Stealth);
        let resolve_hostname = !hostname_numeric.unwrap_or(true) && profile != ProfileType::Stealth;

        let source_ipv4: Option<Ipv4Addr> = match source_ip {
            Some(source_ip) => match source_ip.parse::<Ipv4Addr>() {
                Ok(parsed_ipv4) => Some(parsed_ipv4),
                Err(e) => {
                    return Err(e.to_string());
                }
            },
            None => None,
        };

        let retry_count = match retries {
            Some(retry_count) => retry_count,
            None => match profile {
                ProfileType::Chaos => HOST_RETRY_DEFAULT * 2,
                _ => HOST_RETRY_DEFAULT,
            },
        };

        let scan_timing: ScanTiming =
            ScanOptions::compute_scan_timing(bandwidth, interval, &profile);

        let randomize_targets =
            random.unwrap_or(true) || matches!(profile, ProfileType::Stealth | ProfileType::Chaos);

        let oui_file: String = match oui {
            Some(file) => file.to_string(),
            None => "/usr/share/arp-scan/ieee-oui.csv".to_string(),
        };

        // let packet_help = matches.get_flag("packet_help");

        Ok(Arc::new(ScanOptions {
            profile,
            interface_name,
            network_range,
            timeout_ms,
            resolve_hostname,
            source_ipv4,
            destination_mac,
            source_mac,
            vlan_id,
            retry_count,
            scan_timing,
            randomize_targets,
            // output,
            oui_file,
            hw_type,
            hw_addr,
            proto_type,
            proto_addr,
            arp_operation,
            // packet_help,
            bandwidth,
            interval,
        }))
    }

    pub fn has_vlan(&self) -> bool {
        self.vlan_id.is_some()
        // matches!(&self.vlan_id, Some(_))
    }

    /**
     * Computes scan timing constraints, as requested by the user through CLI
     * arguments. The scan timing constraints will be either expressed in bandwidth
     * (bits per second) or interval between ARP requests (in milliseconds).
     */
    pub fn compute_scan_timing(
        bandwidth: Option<u64>,
        interval: Option<u64>,
        profile: &ProfileType,
    ) -> ScanTiming {
        match (bandwidth, interval) {
            (Some(bandwidth), None) => ScanTiming::Bandwidth(bandwidth),
            (None, Some(interval)) => ScanTiming::Interval(interval),
            _ => match profile {
                ProfileType::Stealth => ScanTiming::Interval(REQUEST_MS_INTERVAL * 2),
                ProfileType::Fast => ScanTiming::Interval(0),
                _ => ScanTiming::Interval(REQUEST_MS_INTERVAL),
            },
        }
    }

    /**
     * Computes the whole network range requested by the user through CLI
     * arguments or files. This method will fail of a failure has been detected
     * (either on the IO level or the network syntax parsing)
     */
    pub fn compute_networks(
        file_value: Option<&String>,
        network_value: Option<&String>,
    ) -> Result<Option<Vec<IpNetwork>>, String> {
        let required_networks: Option<Vec<String>> =
            ScanOptions::list_required_networks(file_value, network_value)?;
        if required_networks.is_none() {
            return Ok(None);
        }

        let mut networks: Vec<IpNetwork> = vec![];
        for network_text in required_networks.unwrap() {
            match IpNetwork::from_str(&network_text) {
                Ok(parsed_network) => {
                    networks.push(parsed_network);
                    Ok(())
                }
                Err(err) => Err(format!("Expected valid IPv4 network range ({})", err)),
            }?;
        }
        Ok(Some(networks))
    }

    fn list_required_networks(
        file_value: Option<&String>,
        network_value: Option<&String>,
    ) -> Result<Option<Vec<String>>, String> {
        let network_options = (file_value, network_value);
        match network_options {
            (Some(file_path), None) => {
                let path = Path::new(file_path);
                fs::read_to_string(path)
                    .map(|content| Some(content.lines().map(|line| line.to_string()).collect()))
                    .map_err(|err| format!("Could not open file {} - {}", file_path, err))
            }
            (None, Some(raw_ranges)) => Ok(Some(
                raw_ranges.split(',').map(|line| line.to_string()).collect(),
            )),
            _ => Ok(None),
        }
    }
}
