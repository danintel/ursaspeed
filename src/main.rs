// Crypto speed microbenchmark program
// Dan Anderson
// © Copyright 2018, Intel Corporation.

extern crate chrono;
extern crate clap;
extern crate os_type;
extern crate rustc_version;
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
use os_type::current_platform;
use rustc_version::{version, version_meta, Channel};
use std::time::{Duration, Instant};
use regex::Regex;

// Hash crates
// XXX: remove use ???
use sha2::{Sha256, Sha512, Digest as Sha2Digest};
use openssl::hash::{Hasher, MessageDigest};
use ring::digest::{Context, SHA256, SHA512};
use amcl::hash256::HASH256;
use amcl::hash512::HASH512;
use ursa::hash::{digest, DigestAlgorithm};


// Crate ring
fn sha256_ring(byte_len: usize, data: [u8; 8192]) {
    let mut h = Context::new(&SHA256);
    let _ = h.update(&data[..byte_len]);
}
fn sha512_ring(byte_len: usize, data: [u8; 8192]) {
    let mut h = Context::new(&SHA512);
    let _ = h.update(&data[..byte_len]);
}

// Crate openssl
fn sha256_openssl(byte_len: usize, data: [u8; 8192]) {
    let mut h = Hasher::new(MessageDigest::sha256()).unwrap();
    let _ = h.update(&data[..byte_len]);
}
fn sha512_openssl(byte_len: usize, data: [u8; 8192]) {
    let mut h = Hasher::new(MessageDigest::sha512()).unwrap();
    let _ = h.update(&data[..byte_len]);
}

// Crate sha2
fn sha256_sha2(byte_len: usize, data: [u8; 8192]) {
    let mut h = Sha256::new();
    h.input(&data[..byte_len]);
}
fn sha512_sha2(byte_len: usize, data: [u8; 8192]) {
    let mut sha2hash = Sha512::new();
    sha2hash.input(&data[..byte_len]);
}

// Crate amcl
fn sha256_amcl(byte_len: usize, data: [u8; 8192]) {
    let mut h = HASH256::new();
    h.process_array(&data[..byte_len]);
}
fn sha512_amcl(byte_len: usize, data: [u8; 8192]) {
    let mut h = HASH512::new();
    h.process_array(&data[..byte_len]);
}

// Crate hashlib
fn sha256_hashlib(byte_len: usize, data: [u8; 8192]) {
    let mut h = Sha256::new();
    let _ = h.input(&data[..byte_len]);
}
fn sha512_hashlib(byte_len: usize, data: [u8; 8192]) {
    let mut h = Sha512::new();
    let _ = h.input(&data[..byte_len]);
}

// Crate ursa
fn sha256_ursa(byte_len: usize, data: [u8; 8192]) {
    let _ = digest(DigestAlgorithm::Sha2_256, &data[..byte_len]).unwrap();
}
fn sha512_ursa(byte_len: usize, data: [u8; 8192]) {
    let _ = digest(DigestAlgorithm::Sha2_512, &data[..byte_len]).unwrap();
}



/// Run a hash function in a loop for timeout_secs
/// with a buffer of byte_len bytes.
/// Return the number of times it looped and elapsed millisec time.
fn hash_loop(hash_function: &Fn(usize, [u8; 8192]),
    byte_len: usize, timeout_secs: u64) -> (u64, u64) {

    let mut count: u64 = 0;
    let data: [u8; 8192] = [0; 8192];
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
    let os = current_platform();
    let rver = version().unwrap();
    let channel = channel_string(version_meta().unwrap().channel);

    println!("Time: {} UTC", time_now.naive_utc());
    println!("OS: {:?} {}", os.os_type, os.version);
    println!("rustc: {}.{}.{} ({} channel)",
        rver.major, rver.minor, rver.patch, channel);
}


/// Run an "openssl speed" style speed test with output.
/// If machine_output true, output is colon-separated on 1 line.
fn run_speed_test(algo_name: &str, hash_function: &Fn(usize, [u8; 8192]),
    timeout_secs: u64, machine_output: bool, kbytes_sec: &mut [f64]) {

    let block_byte_sizes = vec![16, 64, 256, 1024, 8192];
    let mut counts = vec![0, 0, 0, 0, 0];

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
        "   1024 bytes   8192 bytes"));
}


/// Print results from an "openssl speed" style speed test.
/// If machine_output true, output is colon-separated on 1 line.
fn print_speed_test_results(algo_name: &str, time_now: DateTime<Utc>,
    machine_output: bool, kbytes_sec: &mut [f64]) {

    if !machine_output {
        println!(
            "{:14} {:10.2}k {:11.2}k {:11.2}k {:11.2}k {:11.2}k",
            algo_name, kbytes_sec[0], kbytes_sec[1], kbytes_sec[2],
            kbytes_sec[3], kbytes_sec[4]
        );

    } else {
        let os = current_platform();
        let rver = version().unwrap();

        println!(concat!("{}:{:.2}:{:.2}:{:.2}:{:.2}:{:.2}:",
            "{}:{:?}:{}:{}.{}.{}"),
            algo_name, kbytes_sec[0], kbytes_sec[1], kbytes_sec[2],
            kbytes_sec[3], kbytes_sec[4],
            time_now.timestamp(),
            os.os_type, os.version,
            rver.major, rver.minor, rver.patch);
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
    // XXX make macros

    // Crate ring
    let mut ring_sha256_buf = vec![0f64, 0f64, 0f64, 0f64, 0f64];
    let mut ring_sha512_buf = vec![0f64, 0f64, 0f64, 0f64, 0f64];
    if arg_match(regexp, "ring/sha256") {
        run_speed_test(&"ring/sha256", &sha256_ring, 3, machine_output,
            ring_sha256_buf.as_mut_slice());
    }
    if arg_match(regexp, "ring/sha512") {
        run_speed_test(&"ring/sha512", &sha512_ring, 3, machine_output,
            ring_sha512_buf.as_mut_slice());
    }

    // Crate sha2
    let mut sha2_sha256_buf = vec![0f64, 0f64, 0f64, 0f64, 0f64];
    let mut sha2_sha512_buf = vec![0f64, 0f64, 0f64, 0f64, 0f64];
    if arg_match(regexp, "sha2/sha256") {
        run_speed_test(&"sha2/sha256", &sha256_sha2, 3, machine_output,
            sha2_sha256_buf.as_mut_slice());
    }
    if arg_match(regexp, "sha2/sha512") {
        run_speed_test(&"sha2/sha512", &sha512_sha2, 3, machine_output,
            sha2_sha512_buf.as_mut_slice());
    }

    // Crate openssl
    let mut openssl_sha256_buf = vec![0f64, 0f64, 0f64, 0f64, 0f64];
    let mut openssl_sha512_buf = vec![0f64, 0f64, 0f64, 0f64, 0f64];
    if arg_match(regexp, "openssl/sha256") {
        run_speed_test(&"openssl/sha256", &sha256_openssl, 3, machine_output,
            openssl_sha256_buf.as_mut_slice());
    }
    if arg_match(regexp, "openssl/sha512") {
        run_speed_test(&"openssl/sha512", &sha512_openssl, 3, machine_output,
            openssl_sha512_buf.as_mut_slice());
    }

    // Crate amcl
    let mut amcl_sha256_buf = vec![0f64, 0f64, 0f64, 0f64, 0f64];
    let mut amcl_sha512_buf = vec![0f64, 0f64, 0f64, 0f64, 0f64];
    if arg_match(regexp, "amcl/sha256") {
        run_speed_test(&"amcl/sha256", &sha256_amcl, 3, machine_output,
            amcl_sha256_buf.as_mut_slice());
    }
    if arg_match(regexp, "amcl/sha512") {
        run_speed_test(&"amcl/sha512", &sha512_amcl, 3, machine_output,
            amcl_sha512_buf.as_mut_slice());
    }

    // Crate hashlib
    let mut hashlib_sha256_buf = vec![0f64, 0f64, 0f64, 0f64, 0f64];
    let mut hashlib_sha512_buf = vec![0f64, 0f64, 0f64, 0f64, 0f64];
    if arg_match(regexp, "hashlib/sha256") {
        run_speed_test(&"hashlib/sha256", &sha256_hashlib, 3, machine_output,
            hashlib_sha256_buf.as_mut_slice());
    }
    if arg_match(regexp, "hashlib/sha512") {
        run_speed_test(&"hashlib/sha512", &sha512_hashlib, 3, machine_output,
            hashlib_sha512_buf.as_mut_slice());
    }

    // Crate ursa
    let mut ursa_sha256_buf = vec![0f64, 0f64, 0f64, 0f64, 0f64];
    let mut ursa_sha512_buf = vec![0f64, 0f64, 0f64, 0f64, 0f64];
    if arg_match(regexp, "ursa/sha256") {
        run_speed_test(&"ursa/sha256", &sha256_ursa, 3, machine_output,
            ursa_sha256_buf.as_mut_slice());
    }
    if arg_match(regexp, "ursa/sha512") {
        run_speed_test(&"ursa/sha512", &sha512_ursa, 3, machine_output,
            ursa_sha512_buf.as_mut_slice());
    }


    // Print compiler and runtime information
    if !machine_output {
        print_system_info(time_now);
        print_speed_test_results_header();
    }

    // Print results for each algorithm/crate
    // XXX make macros

    // Crate ring
    if arg_match(regexp, "ring/sha256") {
        print_speed_test_results(&"sha256/ring", time_now, machine_output,
            ring_sha256_buf.as_mut_slice());
    }
    if arg_match(regexp, "ring/sha512") {
        print_speed_test_results(&"sha512/ring", time_now, machine_output,
            ring_sha512_buf.as_mut_slice());
    }

    // Crate openssl
    if arg_match(regexp, "openssl/sha256") {
        print_speed_test_results(&"sha256/openssl", time_now, machine_output,
            openssl_sha256_buf.as_mut_slice());
    }
    if arg_match(regexp, "openssl/sha512") {
        print_speed_test_results(&"sha512/openssl", time_now, machine_output,
            openssl_sha512_buf.as_mut_slice());
    }

    // Crate sha2
    if arg_match(regexp, "sha2/sha256") {
        print_speed_test_results(&"sha256/sha2", time_now, machine_output,
            sha2_sha256_buf.as_mut_slice());
    }
    if arg_match(regexp, "sha2/sha512") {
        print_speed_test_results(&"sha512/sha2", time_now, machine_output,
            sha2_sha512_buf.as_mut_slice());
    }

    // Crate amcl
    if arg_match(regexp, "amcl/sha256") {
        print_speed_test_results(&"amcl/sha256", time_now, machine_output,
            amcl_sha256_buf.as_mut_slice());
    }
    if arg_match(regexp, "amcl/sha512") {
        print_speed_test_results(&"amcl/sha512", time_now, machine_output,
            amcl_sha512_buf.as_mut_slice());
    }

    // Crate hashlib
    if arg_match(regexp, "hashlib/sha256") {
        print_speed_test_results(&"hashlib/sha256", time_now, machine_output,
            hashlib_sha256_buf.as_mut_slice());
    }
    if arg_match(regexp, "hashlib/sha512") {
        print_speed_test_results(&"hashlib/sha512", time_now, machine_output,
            hashlib_sha512_buf.as_mut_slice());
    }

    // Crate ursa
    if arg_match(regexp, "ursa/sha256") {
        print_speed_test_results(&"ursa/sha256", time_now, machine_output,
            ursa_sha256_buf.as_mut_slice());
    }
    if arg_match(regexp, "ursa/sha512") {
        print_speed_test_results(&"ursa/sha512", time_now, machine_output,
            ursa_sha512_buf.as_mut_slice());
    }
}