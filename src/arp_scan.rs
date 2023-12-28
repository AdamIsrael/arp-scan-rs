use std::io::{Error, ErrorKind};
use std::net::IpAddr;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::{network, utils, Vendor, ResponseSummary, TargetDetails};
use crate::scan_options::ScanOptions;


#[derive(Debug)]
pub struct ScanResults {
    pub response_summary: ResponseSummary,
    pub target_details: Vec<TargetDetails>,
}
/// Perform an ARP scan
pub fn arp_scan(scan_options: &Arc<ScanOptions>) -> Result<ScanResults, Error> {

    // Start ARP scan operation
    // ------------------------
    // ARP responses on the interface will be collected in a separate thread,
    // while the main thread sends a batch of ARP requests for each IP in the
    // local network.

    let channel_config = pnet_datalink::Config {
        read_timeout: Some(Duration::from_millis(network::DATALINK_RCV_TIMEOUT)),
        ..pnet_datalink::Config::default()
    };

    let interfaces = pnet_datalink::interfaces();

    let (selected_interface, ip_networks) = network::compute_network_configuration(&interfaces, &scan_options);

    let (mut tx, mut rx) = match pnet_datalink::channel(selected_interface, channel_config) {
        Ok(pnet_datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            // eprintln!("Expected an Ethernet datalink channel");
            // return Err("".to_string());
            return Err(Error::new(ErrorKind::Other, "Expected an Ethernet datalink channel."));

            // process::exit(1);
        },
        Err(error) => {
            eprintln!("Datalink channel creation failed ({})", error);
            // return Err("".to_string());
            return Err(Error::new(ErrorKind::Other, "Datalink channel creation failed."));
            // process::exit(1);
        }
    };

    // The 'timed_out' mutex is shared accross the main thread (which performs
    // ARP packet sending) and the response thread (which receives and stores
    // all ARP responses).
    let timed_out = Arc::new(AtomicBool::new(false));
    let cloned_timed_out = Arc::clone(&timed_out);

    let mut vendor_list = Vendor::new(&scan_options.oui_file);

    let cloned_options = Arc::clone(&scan_options);
    let arp_responses = thread::spawn(move || network::receive_arp_responses(&mut rx, cloned_options, cloned_timed_out, &mut vendor_list));

    let network_size = utils::compute_network_size(&ip_networks);
    if network_size.is_err() {
        // return Err(network_size.err().unwrap());
        return Err(Error::new(ErrorKind::Other, network_size.err().unwrap()));
    }
    // match network_size {
    //     Ok(network_size) => {}
    // }
    let estimations = network::compute_scan_estimation(network_size.unwrap(), &scan_options);
    let interval_ms = estimations.interval_ms;

    // if scan_options.is_plain_output() {

    //     let formatted_ms = time::format_milliseconds(estimations.duration_ms);
    //     println!("Estimated scan time {} ({} bytes, {} bytes/s)", formatted_ms, estimations.request_size, estimations.bandwidth);
    //     println!("Sending {} ARP requests (waiting at least {}ms, {}ms request interval)", network_size, scan_options.timeout_ms, interval_ms);
    // }

    let has_reached_timeout = Arc::new(AtomicBool::new(false));
    let cloned_reached_timeout = Arc::clone(&has_reached_timeout);

    ctrlc::set_handler(move || {
        eprintln!("[warn] Receiving halt signal, ending scan with partial results");
        cloned_reached_timeout.store(true, Ordering::Relaxed);
    }).unwrap_or_else(|err| {
        // TODO: Fix this return
        return;
        // return Err("Could not set CTRL+C handler".to_string());
        // eprintln!("Could not set CTRL+C handler ({})", err);
        // process::exit(1);
    });

    let source_ip = network::find_source_ip(selected_interface, scan_options.source_ipv4);

    // The retry count does right now use a 'brute-force' strategy without
    // synchronization process with the already known hosts.
    for _ in 0..scan_options.retry_count {

        if has_reached_timeout.load(Ordering::Relaxed) {
            break;
        }

        let ip_addresses = network::NetworkIterator::new(&ip_networks, scan_options.randomize_targets);

        for ip_address in ip_addresses {

            if has_reached_timeout.load(Ordering::Relaxed) {
                break;
            }

            if let IpAddr::V4(ipv4_address) = ip_address {
                network::send_arp_request(&mut tx, selected_interface, source_ip, ipv4_address, Arc::clone(&scan_options));
                thread::sleep(Duration::from_millis(interval_ms));
            }
        }
    }

    // Once the ARP packets are sent, the main thread will sleep for T seconds
    // (where T is the timeout option). After the sleep phase, the response
    // thread will receive a stop request through the 'timed_out' mutex.
    let mut sleep_ms_mount: u64 = 0;
    while !has_reached_timeout.load(Ordering::Relaxed) && sleep_ms_mount < scan_options.timeout_ms {

        thread::sleep(Duration::from_millis(100));
        sleep_ms_mount += 100;
    }
    timed_out.store(true, Ordering::Relaxed);

    match arp_responses.join() {
        Ok(r) => {
            return Ok(ScanResults { response_summary: r.0, target_details: r.1});
        }
        Err(_) => {
            return Err(Error::new(ErrorKind::Other, ""));
        }
    }

    // let (response_summary, target_details) = arp_responses.join().unwrap_or_else(|error| {
    //     // TODO: implement this return
    //     // return;
    //     // return Err(Error::new(ErrorKind::Other, "over 9000!"));

    //     // eprintln!("Failed to close receive thread ({:?})", error);
    //     // process::exit(1);
    // });
}

