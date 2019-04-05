
target/release/crypto-speed: src/main.rs
	cargo run 2>&1 | cat -v

build:
	cargo build --release 2>&1 | cat -v


run:	test

test:
	target/release/crypto-speed
	openssl speed sha256 sha512
	cpuid | egrep -i 'brand =|avx:|avx2:|avx512f:' | sort -u

machine:
	target/release/crypto-speed -m

clean:
	rm target/release/crypto-speed

