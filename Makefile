
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

# Obtain the generated DTB templates
DTBS = testdata/device-trees
$(DTBS):
	git clone -b main https://jpbrucker.net/git/vmm-dtbs $@

test-dtbs: build-examples $(DTBS)
	@# Parse DTBs, check that the output is stable
	target/debug/examples/dtb $(DTBS)/kvmtool-3.18.dtb
	target/debug/examples/dtb $(DTBS)/qemu-9.1.dtb
TESTS += test-dtbs

test: $(TESTS)
