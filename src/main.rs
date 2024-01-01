use std::net::Ipv4Addr;
use std::process;
use std::sync::Arc;

use ansi_term::Color::Red;
use clap::builder::PossibleValue;
use clap::{Arg, ArgAction, ArgMatches, Command};
use pnet::packet::arp::{ArpHardwareType, ArpOperation};
use pnet::packet::ethernet::EtherType;
use pnet_datalink::MacAddr;
use serde::Serialize;

// use arp_scan;

mod print;
mod time;

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

pub fn parse_clap_args(matches: &ArgMatches) -> Arc<arp_scan::ScanOptions> {
    let mut scan_options = arp_scan::ScanOptionsBuilder::new();

    let profile = match matches.get_one::<String>("profile") {
        Some(output_request) => match output_request.as_ref() {
            "default" | "d" => arp_scan::ProfileType::Default,
            "fast" | "f" => arp_scan::ProfileType::Fast,
            "stealth" | "s" => arp_scan::ProfileType::Stealth,
            "chaos" | "c" => arp_scan::ProfileType::Chaos,
            _ => {
                eprintln!("Expected correct profile name (default/fast/stealth/chaos)");
                process::exit(1);
            }
        },
        None => arp_scan::ProfileType::Default,
    };
    scan_options.profile(profile.clone());

    if let Some(interface_name) = matches.get_one::<String>("interface").cloned() {
        scan_options.interface_name(interface_name);
    }

    let file_option = matches.get_one::<String>("file");
    let network_option = matches.get_one::<String>("network");

    if let Some(network_range) =
        arp_scan::ScanOptions::compute_networks(file_option, network_option).unwrap_or_else(|err| {
            eprintln!("Could not compute requested network range to scan");
            eprintln!("{}", err);
            process::exit(1);
        })
    {
        scan_options.network_range(network_range);
    };

    let timeout_ms: u64 = match matches.get_one::<String>("timeout") {
        Some(timeout_text) => time::parse_to_milliseconds(timeout_text).unwrap_or_else(|err| {
            eprintln!("Expected correct timeout, {}", err);
            process::exit(1);
        }),
        None => match profile {
            arp_scan::ProfileType::Fast => arp_scan::TIMEOUT_MS_FAST,
            _ => arp_scan::TIMEOUT_MS_DEFAULT,
        },
    };
    scan_options.timeout_ms(timeout_ms);

    // Hostnames will not be resolved in numeric mode or stealth profile
    let resolve_hostname =
        !matches.get_flag("numeric") && !matches!(profile, arp_scan::ProfileType::Stealth);
    scan_options.resolve_hostname(resolve_hostname);

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
    scan_options.source_ipv4(source_ipv4);

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
    scan_options.destination_mac(destination_mac);

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
    scan_options.source_mac(source_mac);

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
    scan_options.vlan_id(vlan_id);

    let retry_count = match matches.get_one::<String>("retry_count") {
        Some(retry_count) => match retry_count.parse::<usize>() {
            Ok(retry_number) => retry_number,
            Err(_) => {
                eprintln!("Expected positive number for host retry count");
                process::exit(1);
            }
        },
        None => match profile {
            arp_scan::ProfileType::Chaos => arp_scan::HOST_RETRY_DEFAULT * 2,
            _ => arp_scan::HOST_RETRY_DEFAULT,
        },
    };
    scan_options.retry_count(retry_count);

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
    scan_options.bandwidth(bandwidth);

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
    scan_options.interval(interval);

    let scan_timing: arp_scan::ScanTiming =
        arp_scan::ScanOptions::compute_scan_timing(bandwidth, interval, &profile);
    scan_options.scan_timing(scan_timing);

    let randomize_targets = matches.get_flag("random")
        || matches!(
            profile,
            arp_scan::ProfileType::Stealth | arp_scan::ProfileType::Chaos
        );
    scan_options.randomize_targets(randomize_targets);

    let oui_file: String = match matches.get_one::<String>("oui-file") {
        Some(file) => file.to_string(),
        None => arp_scan::get_oui_file(),
    };
    scan_options.oui_file(oui_file);

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
    scan_options.hw_type(hw_type);

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
    scan_options.hw_addr(hw_addr);

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
    scan_options.proto_type(proto_type);

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
    scan_options.proto_addr(proto_addr);

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
    scan_options.arp_operation(arp_operation);

    Arc::new(scan_options.build().unwrap())
}

/**
 * Display the scan results on stdout with a table. The 'final_result' vector
 * contains all items that will be displayed.
 */
pub fn display_scan_results(
    response_summary: arp_scan::ResponseSummary,
    mut target_details: Vec<arp_scan::TargetDetails>,
    options: &arp_scan::ScanOptions,
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
    response_summary: arp_scan::ResponseSummary,
    target_details: Vec<arp_scan::TargetDetails>,
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
    response_summary: arp_scan::ResponseSummary,
    mut target_details: Vec<arp_scan::TargetDetails>,
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
    response_summary: arp_scan::ResponseSummary,
    mut target_details: Vec<arp_scan::TargetDetails>,
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
    response_summary: arp_scan::ResponseSummary,
    mut target_details: Vec<arp_scan::TargetDetails>,
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
        print::show_interfaces(&interfaces);
        process::exit(0);
    }

    if matches.get_flag("packet_help") {
        print::print_ascii_packet();
        process::exit(0);
    }

    // TODO: Is this actually needed? I don't need root to run it on MacOS.
    if !arp_scan::is_root_user() {
        eprintln!("Should run this binary as root or use --help for options");
        process::exit(1);
    }

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
        let (_, ip_networks) = arp_scan::compute_network_configuration(&interfaces, &scan_options);

        match arp_scan::compute_network_size(&ip_networks) {
            Ok(network_size) => {
                let estimations = arp_scan::compute_scan_estimation(network_size, &scan_options);
                let interval_ms = estimations.interval_ms;

                let formatted_ms = time::format_milliseconds(estimations.duration_ms);
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
