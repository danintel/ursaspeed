
target/debug/crypto-speed: src/main.rs
	cargo run 2>&1 | cat -v

build:
	cargo build 2>&1 | cat -v

optimize:
	cargo build --release 2>&1 | cat -v

run:	test

test:
	target/debug/crypto-speed
	cpuid |egrep -i 'brand =|avx:|avx2:|avx512f:'

machine:
	target/debug/crypto-speed -m

clean:
	rm target/debug/crypto-speed

