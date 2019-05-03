// Crypto speed microbenchmark program
// Dan Anderson
// Copyright ©  2019, Intel Corporation.

extern crate chrono;
extern crate clap;
extern crate os_type;
extern crate rustc_version;
extern crate hostname;
extern crate regex;

// Hash libraries
extern crate ring;
extern crate openssl;
extern crate sha2;
extern crate amcl;
extern crate hashlib;
extern crate ursa;

use std::io::{self, Write};
use chrono::{DateTime, Utc};
use clap::{App, Arg};
use rustc_version::{version, version_meta, Channel};
use std::time::{Duration, Instant};
use regex::Regex;

// Hash crates
use sha2::Digest; // or: use ursa::Digest;
use hashlib::prelude::HashAlgoKernel;

// Crate ring
fn sha256_ring(byte_len: usize, data: [u8; 16384]) {
    ring::digest::digest(&ring::digest::SHA256, &data[..byte_len]);
}
fn sha512_ring(byte_len: usize, data: [u8; 16384]) {
    ring::digest::digest(&ring::digest::SHA256, &data[..byte_len]);
}

// Crate openssl
fn sha256_openssl(byte_len: usize, data: [u8; 16384]) {
    openssl::sha::sha256(&data[..byte_len]);
}
fn sha512_openssl(byte_len: usize, data: [u8; 16384]) {
    openssl::sha::sha512(&data[..byte_len]);
}

// Crate sha2
fn sha256_sha2(byte_len: usize, data: [u8; 16384]) {
    sha2::Sha256::digest(&data[..byte_len]);
}
fn sha512_sha2(byte_len: usize, data: [u8; 16384]) {
    sha2::Sha512::digest(&data[..byte_len]);
}

// Crate amcl
fn sha256_amcl(byte_len: usize, data: [u8; 16384]) {
    let mut h = amcl::hash256::HASH256::new();
    h.process_array(&data[..byte_len]);
    h.hash();
}
fn sha512_amcl(byte_len: usize, data: [u8; 16384]) {
    let mut h = amcl::hash512::HASH512::new();
    //let mut h = HASH512::new();
    h.process_array(&data[..byte_len]);
    h.hash();
}

// Crate hashlib
fn sha256_hashlib(byte_len: usize, data: [u8; 16384]) {
    let mut h = hashlib::sha2::Sha256::new(hashlib::sha2::Sha2Option{});
    let _ = h.update(&data[..byte_len]);
    h.finalize().unwrap();
}

fn sha512_hashlib(byte_len: usize, data: [u8; 16384]) {
    let mut h = hashlib::sha2::Sha512::new(hashlib::sha2::Sha2Option{});
    let _ = h.update(&data[..byte_len]);
    h.finalize().unwrap();
}

// Crate ursa
fn sha256_ursa(byte_len: usize, data: [u8; 16384]) {
    ursa::sha2::Sha256::digest(&data[..byte_len]);
}
fn sha512_ursa(byte_len: usize, data: [u8; 16384]) {
    ursa::sha2::Sha512::digest(&data[..byte_len]);
}



/// Run a hash function in a loop for timeout_secs
/// with a buffer of byte_len bytes.
/// Return the number of times it looped and elapsed millisec time.
fn hash_loop(hash_function: &Fn(usize, [u8; 16384]),
    byte_len: usize, timeout_secs: u64) -> (u64, u64) {

    let mut count: u64 = 0;
    let data: [u8; 16384] = [0; 16384];
    let timer = Instant::now();

    // Loop for timeout_seconds and increment count each time
    loop {
        hash_function(byte_len, data);

        count += 1;
        if timer.elapsed() >= Duration::from_secs(timeout_secs) {
            break;
        }
    }

    let elapsed: u64 =
        timer.elapsed().as_secs() * 1000 +
        timer.elapsed().subsec_millis() as u64;

    (count, elapsed)
}


// Return the string representation of a Channel enum
fn channel_string(channel: Channel) -> &'static str {
    match channel {
        Channel::Stable => "stable",
        Channel::Beta => "beta",
        Channel::Nightly => "nightly",
        Channel::Dev => "dev",
    }
}


/// Print system, compiler, and runtime information
fn print_system_info(time_now: DateTime<Utc>) {
    let os = os_type::current_platform();
    let rver = version().unwrap();
    let channel = channel_string(version_meta().unwrap().channel);

    println!("time: {} UTC", time_now.naive_utc());
    println!("os: {:?} {}", os.os_type, os.version);
    println!("rustc: {}.{}.{} ({} channel)",
        rver.major, rver.minor, rver.patch, channel);
    println!("hostname: {}", hostname::get_hostname().unwrap());
}


/// Run an "openssl speed" style speed test with output.
/// If machine_output true, output is colon-separated on 1 line.
fn run_speed_test(algo_name: &str, hash_function: &Fn(usize, [u8; 16384]),
    timeout_secs: u64, machine_output: bool, kbytes_sec: &mut [f64]) {

    let block_byte_sizes = vec![16, 64, 256, 1024, 8192, 16384];
    let mut counts = vec![0, 0, 0, 0, 0, 0];

    // Run tests with output
    for i in 0..block_byte_sizes.len() {
        let block_usize: usize = block_byte_sizes[i];

        if !machine_output {
            print!("Doing {} for {}s on {} size blocks:",
                algo_name, timeout_secs, block_usize);
            io::stdout().flush().unwrap();
        }

        let (count, elapsed) = hash_loop(hash_function, block_usize,
            timeout_secs);
        counts[i] = count;

        // Calculate kbytes/second for this run
        kbytes_sec[i] = ((count as f64) * (block_usize as f64)) /
            (elapsed as f64);

        if !machine_output {
            println!(" {} {}'s in {}.{:0<2}s",
                counts[i], algo_name, elapsed / 1000, (elapsed % 1000) / 10);
        }
    }
}


/// Print results header lines.
fn print_speed_test_results_header() {
    println!(concat!("The 'numbers' are in 1000s of bytes",
        " per second processed."));
    println!(concat!("type/crate       16 bytes     64 bytes    256 bytes",
        "   1024 bytes   8192 bytes  16384 bytes"));
}


/// Print results from an "openssl speed" style speed test.
/// If machine_output true, output is colon-separated on 1 line.
fn print_speed_test_results(algo_name: &str, time_now: DateTime<Utc>,
    machine_output: bool, kbytes_sec: &mut [f64]) {

    if !machine_output {
        println!(
            "{:14} {:10.2}k {:11.2}k {:11.2}k {:11.2}k {:11.2}k {:11.2}k",
            algo_name, kbytes_sec[0], kbytes_sec[1], kbytes_sec[2],
            kbytes_sec[3], kbytes_sec[4], kbytes_sec[5]
        );

    } else {
        let os = os_type::current_platform();
        let rver = version().unwrap();

        println!(concat!("{}:{:.2}:{:.2}:{:.2}:{:.2}:{:.2}:{:.2}",
            "{}:{:?}:{}:{}.{}.{}:{}"),
            algo_name, kbytes_sec[0], kbytes_sec[1], kbytes_sec[2],
            kbytes_sec[3], kbytes_sec[4], kbytes_sec[5],
            time_now.timestamp(),
            os.os_type, os.version,
            rver.major, rver.minor, rver.patch,
            hostname::get_hostname().unwrap());
    }
}


/// Match a string with a regular expression. Return matching string or None.
fn arg_match(regexp: &str, input: &str) -> bool {
    let re = Regex::new(regexp).unwrap();

    re.is_match(input)
}


/// CLI entry point
fn main() {
    let time_now: DateTime<Utc> = Utc::now();
    let default_regexp = r"\\*";

    // Parse command line
    let matches = App::new("Crypto Speed Microbenchmark Tool.")
        .version("0.1.0")
        .author("Dan Anderson, Intel Corporation.")
        .about(concat!("Run and display crypto microbenchmark.\n\n",
            "EXAMPLES:\n",
            "    ", "crypto-speed", " sha512/openssl\n",
            "    ", "crypto-speed", " \\\\*/openssl\n",
            "    ", "crypto-speed", " -m sha512/\\\\*\n",
            "    ", "crypto-speed", "\n"))
        .arg(Arg::with_name("machine")
                 .short("m")
                 .long("machine")
                 .multiple(false)
                 .help("Display machine-readable output"))
        .arg(Arg::with_name("RegExp")
                 .required(false)
                 .takes_value(true)
                 .index(1)
                 .help("Regular Expression to match algorithm/crate"))
        .get_matches();
    let machine_output: bool = matches.is_present("machine");
    let regexp = matches.value_of("RegExp").unwrap_or(default_regexp);
    // println!("DEBUG: regexp is {}", regexp);
    // println!("foo/bar ? regexp {}={}", regexp, arg_match(regexp, "foo/bar"));


    // Run tests for each algorithm/crate

    // Crate ring
    let mut ring_sha256_buf = vec![0f64, 0f64, 0f64, 0f64, 0f64, 0f64];
    let mut ring_sha512_buf = vec![0f64, 0f64, 0f64, 0f64, 0f64, 0f64];
    if arg_match(regexp, "sha256/ring") {
        run_speed_test(&"sha256/ring", &sha256_ring, 3, machine_output,
            ring_sha256_buf.as_mut_slice());
    }
    if arg_match(regexp, "sha512/ring") {
        run_speed_test(&"sha512/ring", &sha512_ring, 3, machine_output,
            ring_sha512_buf.as_mut_slice());
    }

    // Crate openssl
    let mut openssl_sha256_buf = vec![0f64, 0f64, 0f64, 0f64, 0f64, 0f64];
    let mut openssl_sha512_buf = vec![0f64, 0f64, 0f64, 0f64, 0f64, 0f64];
    if arg_match(regexp, "sha256/openssl") {
        run_speed_test(&"sha256/openssl", &sha256_openssl, 3, machine_output,
            openssl_sha256_buf.as_mut_slice());
    }
    if arg_match(regexp, "sha512/openssl") {
        run_speed_test(&"sha512/openssl", &sha512_openssl, 3, machine_output,
            openssl_sha512_buf.as_mut_slice());
    }

    // Crate sha2
    let mut sha2_sha256_buf = vec![0f64, 0f64, 0f64, 0f64, 0f64, 0f64];
    let mut sha2_sha512_buf = vec![0f64, 0f64, 0f64, 0f64, 0f64, 0f64];
    if arg_match(regexp, "sha256/sha2") {
        run_speed_test(&"sha256/sha2", &sha256_sha2, 3, machine_output,
            sha2_sha256_buf.as_mut_slice());
    }
    if arg_match(regexp, "sha512/sha2") {
        run_speed_test(&"sha512/sha2", &sha512_sha2, 3, machine_output,
            sha2_sha512_buf.as_mut_slice());
    }

    // Crate amcl
    let mut amcl_sha256_buf = vec![0f64, 0f64, 0f64, 0f64, 0f64, 0f64];
    let mut amcl_sha512_buf = vec![0f64, 0f64, 0f64, 0f64, 0f64, 0f64];
    if arg_match(regexp, "sha256/amcl") {
        run_speed_test(&"sha256/amcl", &sha256_amcl, 3, machine_output,
            amcl_sha256_buf.as_mut_slice());
    }
    if arg_match(regexp, "sha512/amcl") {
        run_speed_test(&"sha512/amcl", &sha512_amcl, 3, machine_output,
            amcl_sha512_buf.as_mut_slice());
    }

    // Crate hashlib
    let mut hashlib_sha256_buf = vec![0f64, 0f64, 0f64, 0f64, 0f64, 0f64];
    let mut hashlib_sha512_buf = vec![0f64, 0f64, 0f64, 0f64, 0f64, 0f64];
    if arg_match(regexp, "sha256/hashlib") {
        run_speed_test(&"sha256/hashlib", &sha256_hashlib, 3, machine_output,
            hashlib_sha256_buf.as_mut_slice());
    }
    if arg_match(regexp, "sha512/hashlib") {
        run_speed_test(&"sha512/hashlib", &sha512_hashlib, 3, machine_output,
            hashlib_sha512_buf.as_mut_slice());
    }

    // Crate ursa
    let mut ursa_sha256_buf = vec![0f64, 0f64, 0f64, 0f64, 0f64, 0f64];
    let mut ursa_sha512_buf = vec![0f64, 0f64, 0f64, 0f64, 0f64, 0f64];
    if arg_match(regexp, "sha256/ursa") {
        run_speed_test(&"sha256/ursa", &sha256_ursa, 3, machine_output,
            ursa_sha256_buf.as_mut_slice());
    }
    if arg_match(regexp, "sha512/ursa") {
        run_speed_test(&"sha512/ursa", &sha512_ursa, 3, machine_output,
            ursa_sha512_buf.as_mut_slice());
    }


    // Print compiler and runtime information
    if !machine_output {
        print_system_info(time_now);
        print_speed_test_results_header();
    }

    // Print results for each algorithm/crate

    // Crate ring
    if arg_match(regexp, "sha256/ring") {
        print_speed_test_results(&"sha256/ring", time_now, machine_output,
            ring_sha256_buf.as_mut_slice());
    }
    if arg_match(regexp, "sha512/ring") {
        print_speed_test_results(&"sha512/ring", time_now, machine_output,
            ring_sha512_buf.as_mut_slice());
    }

    // Crate openssl
    if arg_match(regexp, "sha256/openssl") {
        print_speed_test_results(&"sha256/openssl", time_now, machine_output,
            openssl_sha256_buf.as_mut_slice());
    }
    if arg_match(regexp, "sha512/openssl") {
        print_speed_test_results(&"sha512/openssl", time_now, machine_output,
            openssl_sha512_buf.as_mut_slice());
    }

    // Crate sha2
    if arg_match(regexp, "sha256/sha2") {
        print_speed_test_results(&"sha256/sha2", time_now, machine_output,
            sha2_sha256_buf.as_mut_slice());
    }
    if arg_match(regexp, "sha512/sha2") {
        print_speed_test_results(&"sha512/sha2", time_now, machine_output,
            sha2_sha512_buf.as_mut_slice());
    }

    // Crate amcl
    if arg_match(regexp, "sha256/amcl") {
        print_speed_test_results(&"sha256/amcl", time_now, machine_output,
            amcl_sha256_buf.as_mut_slice());
    }
    if arg_match(regexp, "sha512/amcl") {
        print_speed_test_results(&"sha512/amcl", time_now, machine_output,
            amcl_sha512_buf.as_mut_slice());
    }

    // Crate hashlib
    if arg_match(regexp, "sha256/hashlib") {
        print_speed_test_results(&"sha256/hashlib", time_now, machine_output,
            hashlib_sha256_buf.as_mut_slice());
    }
    if arg_match(regexp, "sha512/hashlib") {
        print_speed_test_results(&"sha512/hashlib", time_now, machine_output,
            hashlib_sha512_buf.as_mut_slice());
    }

    // Crate ursa
    if arg_match(regexp, "sha256/ursa") {
        print_speed_test_results(&"sha256/ursa", time_now, machine_output,
            ursa_sha256_buf.as_mut_slice());
    }
    if arg_match(regexp, "sha512/ursa") {
        print_speed_test_results(&"sha512/ursa", time_now, machine_output,
            ursa_sha512_buf.as_mut_slice());
    }
}
