# Ursa Speed
Ursa Speed is a microbenchmark for the Hyperledger Ursa libursa library.

## Introduction
This microbenchmark is intended to run microbenchmarks for popular crypto algorithms in libursa.
For easy comparison, the tests and output are similar to the "openssl speed" microbenchmark.
A microbenchmark is intended only to measure crypto performance, so has no network or disk I/O overhead.

Initially only SHA-2 algorithms are being benchmarked (SHA-256 and SHA-512).
SHA-384 is omitted because it's basically the same as SHA-512 in terms of performance.

In the future, I may add tests for signing and signature verification.

## Prerequisites
This benchmark assumes the ursa repository is installed and built in the parent library, `../ursa`. To download and build, type:

git clone https://github.com/hyperledger/ursa
cd ursa/libursa
cargo build --release

This builds libursa.so in "secure" mode (with C/Rust optimizations).
For more information on Ursa, see
https://github.com/hyperledger/ursa/blob/master/README.md
and
https://www.hyperledger.org/projects/ursa


## Usage

To build and run, type
```
cargo build
```
To run the libursa and openssl microbenchmarks, type:
```
target/debug/crypto-speed
openssl speed
cpuid |egrep -i 'brand =|avx:|avx2:|avx512f:'
```


## Contributing
This software is Apache 2.0 licensed and accepts contributions via
[GitHub](https://github.com/danintel/sawtooth-faq) pull requests.
Each commit must include a `Signed-off-by:` in the commit message (`git commit -s`). This sign-off means you agree the commit satisfies the [Developer Certificate of Origin (DCO).](https://developercertificate.org/)

This example software is derived from the
[Sawtooth Simplewallet](https://github.com/askmish/sawtooth-simplewallet)
application.
Simplewallet supports more programming languages and handles transactions with multiple keys.

## License
This example and Hyperledger Sawtooth software are licensed under the [Apache License Version 2.0](LICENSE) software license.

© Copyright 2019, Intel Corporation.

