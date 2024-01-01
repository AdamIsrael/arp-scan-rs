use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::str::FromStr;

use derive_builder::Builder;
use ipnetwork::IpNetwork;
use pnet::packet::arp::{ArpHardwareType, ArpOperation};
use pnet::packet::ethernet::EtherType;
use pnet_datalink::MacAddr;

use super::utils;
use crate::select_default_interface;

pub const TIMEOUT_MS_FAST: u64 = 800;
pub const TIMEOUT_MS_DEFAULT: u64 = 2000;

pub const HOST_RETRY_DEFAULT: usize = 1;
pub const REQUEST_MS_INTERVAL: u64 = 10;

pub const OUI_FILE: &str = "~/.local/share/ieee/oui.csv";

#[derive(Clone, Debug, PartialEq)]
pub enum ProfileType {
    Default,
    Fast,
    Stealth,
    Chaos,
}

#[derive(Clone, Debug)]
pub enum ScanTiming {
    Interval(u64),
    Bandwidth(u64),
}

#[derive(Builder, Clone, Debug)]
#[builder(setter(into))]
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
    pub oui_file: String,
    pub hw_type: Option<ArpHardwareType>,
    pub hw_addr: Option<u8>,
    pub proto_type: Option<EtherType>,
    pub proto_addr: Option<u8>,
    pub arp_operation: Option<ArpOperation>,
    pub bandwidth: Option<u64>,
    pub interval: Option<u64>,
}

impl ScanOptions {
    pub fn has_vlan(&self) -> bool {
        self.vlan_id.is_some()
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

impl ScanOptionsBuilder {
    /// Create a ScanOptionsBuilder with default values
    pub fn new() -> Self {
        let profile = ProfileType::Default;
        let interfaces = pnet_datalink::interfaces();
        let interface = select_default_interface(&interfaces);
        let interface_name = Some(interface.unwrap().name);

        let network_range = ScanOptions::compute_networks(None, None).unwrap();

        let resolve_hostname = true;

        let scan_timing = ScanOptions::compute_scan_timing(None, None, &profile);

        let oui_file = utils::get_oui_file();

        ScanOptionsBuilder {
            profile: Some(profile),
            interface_name: Some(interface_name),
            network_range: Some(network_range),
            timeout_ms: Some(TIMEOUT_MS_DEFAULT),
            resolve_hostname: Some(resolve_hostname),
            source_ipv4: None,
            destination_mac: None,
            source_mac: None,
            vlan_id: None,
            retry_count: Some(HOST_RETRY_DEFAULT),
            scan_timing: Some(scan_timing),
            randomize_targets: Some(false),
            oui_file: Some(oui_file),
            hw_type: None,
            hw_addr: None,
            proto_type: None,
            proto_addr: None,
            arp_operation: None,
            bandwidth: None,
            interval: None,
        }
    }
}
