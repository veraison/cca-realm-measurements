
.DEFAULT_GOAL := test

build-debug:
	cargo build
TESTS += build-debug

build-release:
	cargo build --release
TESTS += build-release

build-examples:
	cargo build --examples
TESTS += build-examples

clippy:
	cargo clippy --workspace
TESTS += clippy

clippy-examples:
	cargo clippy --examples
TESTS += clippy-examples

clippy-tests:
	cargo clippy --tests
TESTS += clippy-tests

run-tests:
	cargo test --workspace -- --nocapture
TESTS += run-tests

doc:
	cargo doc --workspace
TESTS += doc

test-dtbs: build-examples
	@# Parse DTBs, check that the output is stable
	target/debug/examples/dtb device-trees/kvmtool-3.18.dtb
	target/debug/examples/dtb device-trees/qemu-9.1.dtb
TESTS += test-dtbs

test: $(TESTS)
