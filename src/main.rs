extern crate arp_scan;

// use std::io::{Error, ErrorKind};
use std::net::Ipv4Addr;
use std::process;
use std::sync::Arc;

use ansi_term::Color::{Green, Red};
use clap::builder::PossibleValue;
use clap::{Arg, ArgAction, ArgMatches, Command};
use pnet::packet::arp::{ArpHardwareType, ArpOperation};
use pnet::packet::ethernet::EtherType;
use pnet_datalink::MacAddr;
use serde::Serialize;

use arp_scan::{
    compute_network_configuration, compute_network_size, compute_scan_estimation, ProfileType,
    ResponseSummary, ScanOptions, ScanTiming, TargetDetails, HOST_RETRY_DEFAULT,
    print_ascii_packet, show_interfaces,
    TIMEOUT_MS_DEFAULT, TIMEOUT_MS_FAST,
};
// use arp_scan::utils;

const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");

const EXAMPLES_HELP: &str = "EXAMPLES:

    # Launch a default scan with on the first working interface
    arp-scan

    # List network interfaces
    arp-scan -l

    # Launch a scan on a specific range
    arp-scan -i eth0 -n 10.37.3.1,10.37.4.55/24

    # Launch a scan on WiFi interface with fake IP and stealth profile
    arp-scan -i eth0 --source-ip 192.168.0.42 --profile stealth

    # Launch a scan on VLAN 45 with JSON output
    arp-scan -Q 45 -o json

";

enum OutputFormat {
    Plain,
    Json,
    Yaml,
    Csv,
}
/* Parse a given time string into milliseconds. This can be used to convert a
 * string such as '20ms', '10s' or '1h' into adequate milliseconds. Without
 * suffix, the default behavior is to parse into milliseconds.
 */
fn parse_to_milliseconds(time_arg: &str) -> Result<u64, &str> {
    let len = time_arg.len();

    if time_arg.ends_with("ms") {
        let milliseconds_text = &time_arg[0..len - 2];
        return match milliseconds_text.parse::<u64>() {
            Ok(ms_value) => Ok(ms_value),
            Err(_) => Err("invalid milliseconds"),
        };
    }

    if time_arg.ends_with('s') {
        let seconds_text = &time_arg[0..len - 1];
        return match seconds_text.parse::<u64>().map(|value| value * 1000) {
            Ok(ms_value) => Ok(ms_value),
            Err(_) => Err("invalid seconds"),
        };
    }

    if time_arg.ends_with('m') {
        let seconds_text = &time_arg[0..len - 1];
        return match seconds_text.parse::<u64>().map(|value| value * 1000 * 60) {
            Ok(ms_value) => Ok(ms_value),
            Err(_) => Err("invalid minutes"),
        };
    }

    if time_arg.ends_with('h') {
        let hour_text = &time_arg[0..len - 1];
        return match hour_text.parse::<u64>().map(|value| value * 1000 * 60 * 60) {
            Ok(ms_value) => Ok(ms_value),
            Err(_) => Err("invalid hours"),
        };
    }

    match time_arg.parse::<u64>() {
        Ok(ms_value) => Ok(ms_value),
        Err(_) => Err("invalid milliseconds"),
    }
}

/**
 * This function groups together all exposed CLI arguments to the end-users
 * with clap. Other CLI details (version, ...) should be grouped there as well.
 */
pub fn build_args() -> Command {
    Command::new("arp-scan")
        .version(CLI_VERSION)
        .about("A minimalistic ARP scan tool written in Rust")
        .arg(
            Arg::new("profile")
                .short('p')
                .long("profile")
                .value_name("PROFILE_NAME")
                .value_parser([
                    PossibleValue::new("default").help("Default scan profile"),
                    PossibleValue::new("fast").help("Fast ARP scans (less accurate)"),
                    PossibleValue::new("stealth").help("Slower scans (minimize impact)"),
                    PossibleValue::new("chaos").help("Randomly-selected values"),
                ])
                .help("Scan profile - a preset of ARP scan options"),
        )
        .arg(
            Arg::new("interface")
                .short('i')
                .long("interface")
                .value_name("INTERFACE_NAME")
                .help("Network interface (defaults to first 'up' interface with IPv4)"),
        )
        .arg(
            Arg::new("network")
                .short('n')
                .long("network")
                .value_name("NETWORK_RANGE")
                .help("Network range to scan (defaults to first IPv4 network on the interface)"),
        )
        .arg(
            Arg::new("file")
                .short('f')
                .long("file")
                .value_name("FILE_PATH")
                .conflicts_with("network")
                .help("Read IPv4 addresses from a file"),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .value_name("TIMEOUT_DURATION")
                .help("ARP response timeout (2000ms)"),
        )
        .arg(
            Arg::new("source_ip")
                .short('S')
                .long("source-ip")
                .value_name("SOURCE_IPV4")
                .help("Source IPv4 address (defaults to IPv4 address on the interface)"),
        )
        .arg(
            Arg::new("destination_mac")
                .short('M')
                .long("dest-mac")
                .value_name("DESTINATION_MAC")
                .help("Destination MAC address for requests"),
        )
        .arg(
            Arg::new("source_mac")
                .long("source-mac")
                .value_name("SOURCE_MAC")
                .help("Source MAC address for requests (default to 00:00:00:00:00:00)"),
        )
        .arg(
            Arg::new("numeric")
                .long("numeric")
                .action(ArgAction::SetTrue)
                .help("Numeric mode, no hostname resolution"),
        )
        .arg(
            Arg::new("vlan")
                .short('Q')
                .long("vlan")
                .value_name("VLAN_ID")
                .help("Send using 802.1Q with VLAN ID"),
        )
        .arg(
            Arg::new("retry_count")
                .short('r')
                .long("retry")
                .value_name("RETRY_COUNT")
                .help("Host retry attempt count (default to 1)"),
        )
        .arg(
            Arg::new("random")
                .short('R')
                .long("random")
                .action(ArgAction::SetTrue)
                .help("Randomize the target list"),
        )
        .arg(
            Arg::new("interval")
                .short('I')
                .long("interval")
                .value_name("INTERVAL_DURATION")
                .help("Milliseconds between ARP requests (defaults to 10ms)"),
        )
        .arg(
            Arg::new("bandwidth")
                .short('B')
                .long("bandwidth")
                .value_name("BITS")
                .conflicts_with("interval")
                .help("Limit scan bandwidth (bits/second)"),
        )
        .arg(
            Arg::new("oui-file")
                .long("oui-file")
                .value_name("FILE_PATH")
                .default_value("/usr/share/arp-scan/ieee-oui.csv")
                .help("Path to custom IEEE OUI CSV file for vendor lookup"),
        )
        .arg(
            Arg::new("list")
                .short('l')
                .long("list")
                .action(ArgAction::SetTrue)
                .exclusive(true)
                .help("List network interfaces and exit"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FORMAT")
                .value_parser([
                    PossibleValue::new("plain").help("Verbose output with table"),
                    PossibleValue::new("json").help("JSON format"),
                    PossibleValue::new("yaml").help("YAML format"),
                    PossibleValue::new("csv").help("CSV format"),
                ])
                .help("Define output format"),
        )
        .arg(
            Arg::new("hw_type")
                .long("hw-type")
                .value_name("HW_TYPE")
                .help("Custom ARP hardware field"),
        )
        .arg(
            Arg::new("hw_addr")
                .long("hw-addr")
                .value_name("ADDRESS_LEN")
                .help("Custom ARP hardware address length"),
        )
        .arg(
            Arg::new("proto_type")
                .long("proto-type")
                .value_name("PROTO_TYPE")
                .help("Custom ARP proto type"),
        )
        .arg(
            Arg::new("proto_addr")
                .long("proto-addr")
                .value_name("ADDRESS_LEN")
                .help("Custom ARP proto address length"),
        )
        .arg(
            Arg::new("arp_operation")
                .long("arp-op")
                .value_name("OPERATION_ID")
                .help("Custom ARP operation ID"),
        )
        .arg(
            Arg::new("packet_help")
                .long("packet-help")
                .action(ArgAction::SetTrue)
                .exclusive(true)
                .help("Print details about an ARP packet and exit"),
        )
        .after_help(EXAMPLES_HELP)
}

pub fn parse_clap_args(matches: &ArgMatches) -> Arc<ScanOptions> {
    let profile = match matches.get_one::<String>("profile") {
        Some(output_request) => match output_request.as_ref() {
            "default" | "d" => ProfileType::Default,
            "fast" | "f" => ProfileType::Fast,
            "stealth" | "s" => ProfileType::Stealth,
            "chaos" | "c" => ProfileType::Chaos,
            _ => {
                eprintln!("Expected correct profile name (default/fast/stealth/chaos)");
                process::exit(1);
            }
        },
        None => ProfileType::Default,
    };

    let interface_name = matches.get_one::<String>("interface").cloned();

    let file_option = matches.get_one::<String>("file");
    let network_option = matches.get_one::<String>("network");

    let network_range =
        ScanOptions::compute_networks(file_option, network_option).unwrap_or_else(|err| {
            eprintln!("Could not compute requested network range to scan");
            eprintln!("{}", err);
            process::exit(1);
        });

    let timeout_ms: u64 = match matches.get_one::<String>("timeout") {
        Some(timeout_text) => parse_to_milliseconds(timeout_text).unwrap_or_else(|err| {
            eprintln!("Expected correct timeout, {}", err);
            process::exit(1);
        }),
        None => match profile {
            ProfileType::Fast => TIMEOUT_MS_FAST,
            _ => TIMEOUT_MS_DEFAULT,
        },
    };

    // Hostnames will not be resolved in numeric mode or stealth profile
    let resolve_hostname = !matches.get_flag("numeric") && !matches!(profile, ProfileType::Stealth);

    let source_ipv4: Option<Ipv4Addr> = match matches.get_one::<String>("source_ip") {
        Some(source_ip) => match source_ip.parse::<Ipv4Addr>() {
            Ok(parsed_ipv4) => Some(parsed_ipv4),
            Err(_) => {
                eprintln!("Expected valid IPv4 as source IP");
                process::exit(1);
            }
        },
        None => None,
    };

    let destination_mac: Option<MacAddr> = match matches.get_one::<String>("destination_mac") {
        Some(mac_address) => match mac_address.parse::<MacAddr>() {
            Ok(parsed_mac) => Some(parsed_mac),
            Err(_) => {
                eprintln!("Expected valid MAC address as destination");
                process::exit(1);
            }
        },
        None => None,
    };

    let source_mac: Option<MacAddr> = match matches.get_one::<String>("source_mac") {
        Some(mac_address) => match mac_address.parse::<MacAddr>() {
            Ok(parsed_mac) => Some(parsed_mac),
            Err(_) => {
                eprintln!("Expected valid MAC address as source");
                process::exit(1);
            }
        },
        None => None,
    };

    let vlan_id: Option<u16> = match matches.get_one::<String>("vlan") {
        Some(vlan) => match vlan.parse::<u16>() {
            Ok(vlan_number) => Some(vlan_number),
            Err(_) => {
                eprintln!("Expected valid VLAN identifier");
                process::exit(1);
            }
        },
        None => None,
    };

    let retry_count = match matches.get_one::<String>("retry_count") {
        Some(retry_count) => match retry_count.parse::<usize>() {
            Ok(retry_number) => retry_number,
            Err(_) => {
                eprintln!("Expected positive number for host retry count");
                process::exit(1);
            }
        },
        None => match profile {
            ProfileType::Chaos => HOST_RETRY_DEFAULT * 2,
            _ => HOST_RETRY_DEFAULT,
        },
    };

    let bandwidth = match matches.get_one::<String>("bandwidth") {
        Some(bandwidth) => match bandwidth.parse::<u64>() {
            Ok(bandwidth) => Some(bandwidth),
            Err(_) => {
                eprintln!("Expected valid VLAN identifier");
                process::exit(1);
            }
        },
        None => None,
    };

    let interval = match matches.get_one::<String>("interval") {
        Some(interval) => match interval.parse::<u64>() {
            Ok(interval) => Some(interval),
            Err(_) => {
                eprintln!("Expected valid VLAN identifier");
                process::exit(1);
            }
        },
        None => None,
    };

    let scan_timing: ScanTiming = ScanOptions::compute_scan_timing(bandwidth, interval, &profile);

    let output = match matches.get_one::<String>("output") {
        Some(output_request) => match output_request.as_ref() {
            "json" => OutputFormat::Json,
            "yaml" => OutputFormat::Yaml,
            "plain" | "text" => OutputFormat::Plain,
            "csv" => OutputFormat::Csv,
            _ => {
                eprintln!("Expected correct output format (json/yaml/plain)");
                process::exit(1);
            }
        },
        None => OutputFormat::Plain,
    };

    let randomize_targets =
        matches.get_flag("random") || matches!(profile, ProfileType::Stealth | ProfileType::Chaos);

    let oui_file: String = match matches.get_one::<String>("oui-file") {
        Some(file) => file.to_string(),
        None => "/usr/share/arp-scan/ieee-oui.csv".to_string(),
    };

    let hw_type = match matches.get_one::<String>("hw_type") {
        Some(hw_type_text) => match hw_type_text.parse::<u16>() {
            Ok(type_number) => Some(ArpHardwareType::new(type_number)),
            Err(_) => {
                eprintln!("Expected valid ARP hardware type number");
                process::exit(1);
            }
        },
        None => None,
    };

    let hw_addr = match matches.get_one::<String>("hw_addr") {
        Some(hw_addr_text) => match hw_addr_text.parse::<u8>() {
            Ok(addr_length) => Some(addr_length),
            Err(_) => {
                eprintln!("Expected valid ARP hardware address length");
                process::exit(1);
            }
        },
        None => None,
    };

    let proto_type = match matches.get_one::<String>("proto_type") {
        Some(proto_type_text) => match proto_type_text.parse::<u16>() {
            Ok(type_number) => Some(EtherType::new(type_number)),
            Err(_) => {
                eprintln!("Expected valid ARP proto type number");
                process::exit(1);
            }
        },
        None => None,
    };

    let proto_addr = match matches.get_one::<String>("proto_addr") {
        Some(proto_addr_text) => match proto_addr_text.parse::<u8>() {
            Ok(addr_length) => Some(addr_length),
            Err(_) => {
                eprintln!("Expected valid ARP hardware address length");
                process::exit(1);
            }
        },
        None => None,
    };

    let arp_operation = match matches.get_one::<String>("arp_operation") {
        Some(arp_op_text) => match arp_op_text.parse::<u16>() {
            Ok(op_number) => Some(ArpOperation::new(op_number)),
            Err(_) => {
                eprintln!("Expected valid ARP operation number");
                process::exit(1);
            }
        },
        None => None,
    };

    let packet_help: bool = matches.get_flag("packet_help");

    Arc::new(ScanOptions {
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
    })
}

/**
 * Display the scan results on stdout with a table. The 'final_result' vector
 * contains all items that will be displayed.
 */
pub fn display_scan_results(
    response_summary: ResponseSummary,
    mut target_details: Vec<TargetDetails>,
    options: &ScanOptions,
) {
    target_details.sort_by_key(|item| item.ipv4);

    let mut hostname_len = 15;
    let mut vendor_len = 15;
    for detail in target_details.iter() {
        if let Some(hostname) = &detail.hostname {
            if hostname.len() > hostname_len {
                hostname_len = hostname.len();
            }
        }

        if let Some(vendor) = &detail.vendor {
            if vendor.len() > vendor_len {
                vendor_len = vendor.len();
            }
        }
    }

    if !target_details.is_empty() {
        println!();
        println!(
            "| IPv4            | MAC               | {: <h_max$} | {: <v_max$} |",
            "Hostname",
            "Vendor",
            h_max = hostname_len,
            v_max = vendor_len
        );
        println!(
            "|-----------------|-------------------|-{:-<h_max$}-|-{:-<v_max$}-|",
            "",
            "",
            h_max = hostname_len,
            v_max = vendor_len
        );
    }

    for detail in target_details.iter() {
        let hostname: &str = match &detail.hostname {
            Some(hostname) => hostname,
            None if !options.resolve_hostname => "(disabled)",
            None => "",
        };
        let vendor: &str = match &detail.vendor {
            Some(vendor) => vendor,
            None => "",
        };
        println!(
            "| {: <15} | {: <18} | {: <h_max$} | {: <v_max$} |",
            detail.ipv4,
            detail.mac,
            hostname,
            vendor,
            h_max = hostname_len,
            v_max = vendor_len
        );
    }

    println!();
    print!("ARP scan finished, ");
    let target_count = target_details.len();
    match target_count {
        0 => print!("{}", Red.paint("no hosts found")),
        1 => print!("1 host found"),
        _ => print!("{} hosts found", target_count),
    }
    let seconds_duration = (response_summary.duration_ms as f32) / (1000_f32);
    println!(" in {:.3} seconds", seconds_duration);

    match response_summary.packet_count {
        0 => print!("No packets received, "),
        1 => print!("1 packet received, "),
        _ => print!("{} packets received, ", response_summary.packet_count),
    };
    match response_summary.arp_count {
        0 => println!("no ARP packets filtered"),
        1 => println!("1 ARP packet filtered"),
        _ => println!("{} ARP packets filtered", response_summary.arp_count),
    };
    println!();
}

#[derive(Serialize)]
struct SerializableResultItem {
    ipv4: String,
    mac: String,
    hostname: String,
    vendor: String,
}

#[derive(Serialize)]
struct SerializableGlobalResult {
    packet_count: usize,
    arp_count: usize,
    duration_ms: u128,
    results: Vec<SerializableResultItem>,
}

/**
 * Transforms an ARP scan result (including KPI and target details) to a structure
 * that can be serialized for export (JSON, YAML, CSV, ...)
 */
fn get_serializable_result(
    response_summary: ResponseSummary,
    target_details: Vec<TargetDetails>,
) -> SerializableGlobalResult {
    let exportable_results: Vec<SerializableResultItem> = target_details
        .into_iter()
        .map(|detail| {
            let hostname = match &detail.hostname {
                Some(hostname) => hostname.clone(),
                None => String::from(""),
            };

            let vendor = match &detail.vendor {
                Some(vendor) => vendor.clone(),
                None => String::from(""),
            };

            SerializableResultItem {
                ipv4: format!("{}", detail.ipv4),
                mac: format!("{}", detail.mac),
                hostname,
                vendor,
            }
        })
        .collect();

    SerializableGlobalResult {
        packet_count: response_summary.packet_count,
        arp_count: response_summary.arp_count,
        duration_ms: response_summary.duration_ms,
        results: exportable_results,
    }
}

/**
 * Export the scan results as a JSON string with response details (timings, ...)
 * and ARP results from the local network.
 */
pub fn export_to_json(
    response_summary: ResponseSummary,
    mut target_details: Vec<TargetDetails>,
) -> String {
    target_details.sort_by_key(|item| item.ipv4);

    let global_result = get_serializable_result(response_summary, target_details);

    serde_json::to_string(&global_result).unwrap_or_else(|err| {
        eprintln!("Could not export JSON results ({})", err);
        process::exit(1);
    })
}

/**
 * Export the scan results as a YAML string with response details (timings, ...)
 * and ARP results from the local network.
 */
pub fn export_to_yaml(
    response_summary: ResponseSummary,
    mut target_details: Vec<TargetDetails>,
) -> String {
    target_details.sort_by_key(|item| item.ipv4);

    let global_result = get_serializable_result(response_summary, target_details);

    serde_yaml::to_string(&global_result).unwrap_or_else(|err| {
        eprintln!("Could not export YAML results ({})", err);
        process::exit(1);
    })
}

/**
 * Export the scan results as a CSV string with response details (timings, ...)
 * and ARP results from the local network.
 */
pub fn export_to_csv(
    response_summary: ResponseSummary,
    mut target_details: Vec<TargetDetails>,
) -> String {
    target_details.sort_by_key(|item| item.ipv4);

    let global_result = get_serializable_result(response_summary, target_details);

    let mut wtr = csv::Writer::from_writer(vec![]);

    for result in global_result.results {
        wtr.serialize(result).unwrap_or_else(|err| {
            eprintln!("Could not serialize result to CSV ({})", err);
            process::exit(1);
        });
    }
    wtr.flush().unwrap_or_else(|err| {
        eprintln!("Could not flush CSV writer buffer ({})", err);
        process::exit(1);
    });

    let convert_writer = wtr.into_inner().unwrap_or_else(|err| {
        eprintln!("Could not convert final CSV result ({})", err);
        process::exit(1);
    });
    String::from_utf8(convert_writer).unwrap_or_else(|err| {
        eprintln!("Could not convert final CSV result to text ({})", err);
        process::exit(1);
    })
}

/**
 * Format milliseconds to a human-readable string. This will of course give an
 * approximation, but will be readable.
 */
pub fn format_milliseconds(milliseconds: u128) -> String {
    if milliseconds < 1000 {
        return format!("{}ms", milliseconds);
    }

    if milliseconds < 1000 * 60 {
        let seconds = milliseconds / 1000;
        return format!("{}s", seconds);
    }

    if milliseconds < 1000 * 60 * 60 {
        let minutes = milliseconds / 1000 / 60;
        return format!("{}m", minutes);
    }

    let hours: u128 = milliseconds / 1000 / 60 / 60;
    format!("{}h", hours)
}

fn main() {
    let matches = build_args().get_matches();
    let scan_options = parse_clap_args(&matches);

    // Find interfaces & list them if requested
    // ----------------------------------------
    // All network interfaces are retrieved and will be listed if the '--list'
    // flag has been given in the request. Note that this can be done without
    // using a root account (this will be verified later).

    let interfaces = pnet_datalink::interfaces();

    if matches.get_flag("list") {
        show_interfaces(&interfaces);
        process::exit(0);
    }

    if matches.get_flag("packet_help") {
        print_ascii_packet();
        process::exit(0);
    }
    // if scan_options.request_protocol_print() {
    //     utils::print_ascii_packet();
    //     process::exit(0);
    // }

    // if !utils::is_root_user() {
    //     eprintln!("Should run this binary as root or use --help for options");
    //     process::exit(1);
    // }

    // All network interfaces are retrieved and will be listed if the '--list'
    // flag has been given in the request. Note that this can be done without
    // using a root account (this will be verified later).

    let interfaces = pnet_datalink::interfaces();

    let output = match matches.get_one::<String>("output") {
        Some(output_request) => match output_request.as_ref() {
            "json" => OutputFormat::Json,
            "yaml" => OutputFormat::Yaml,
            "plain" | "text" => OutputFormat::Plain,
            "csv" => OutputFormat::Csv,
            _ => {
                eprintln!("Expected correct output format (json/yaml/plain)");
                process::exit(1);
            }
        },
        None => OutputFormat::Plain,
    };

    if matches!(output, OutputFormat::Plain) {
        let interfaces = pnet_datalink::interfaces();

        let (_, ip_networks) = compute_network_configuration(&interfaces, &scan_options);

        match compute_network_size(&ip_networks) {
            Ok(network_size) => {
                let estimations = compute_scan_estimation(network_size, &scan_options);
                let interval_ms = estimations.interval_ms;

                let formatted_ms = format_milliseconds(estimations.duration_ms);
                println!(
                    "Estimated scan time {} ({} bytes, {} bytes/s)",
                    formatted_ms, estimations.request_size, estimations.bandwidth
                );
                println!(
                    "Sending {} ARP requests (waiting at least {}ms, {}ms request interval)",
                    network_size, scan_options.timeout_ms, interval_ms
                );
            }
            Err(err) => {
                eprintln!("Could not compute network size: ({})", err);
                process::exit(1);
            }
        }
    }

    match arp_scan::arp_scan(&scan_options) {
        Ok(res) => {
            let response_summary = res.response_summary;
            let target_details = res.target_details;

            let output = match matches.get_one::<String>("output") {
                Some(output_request) => match output_request.as_ref() {
                    "json" => OutputFormat::Json,
                    "yaml" => OutputFormat::Yaml,
                    "plain" | "text" => OutputFormat::Plain,
                    "csv" => OutputFormat::Csv,
                    _ => {
                        eprintln!("Expected correct output format (json/yaml/plain)");
                        process::exit(1);
                    }
                },
                None => OutputFormat::Plain,
            };

            match output {
                OutputFormat::Plain => {
                    display_scan_results(response_summary, target_details, &scan_options)
                }
                OutputFormat::Json => {
                    println!("{}", export_to_json(response_summary, target_details))
                }
                OutputFormat::Yaml => {
                    println!("{}", export_to_yaml(response_summary, target_details))
                }
                OutputFormat::Csv => print!("{}", export_to_csv(response_summary, target_details)),
            }
        }
        Err(e) => {
            panic!("{}", e.to_string());
        }
    };
}
