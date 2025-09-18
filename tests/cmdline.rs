/// Run the realm-measurements command with various parameters
use assert_cmd::prelude::*;
use assert_fs::prelude::*;
use predicates::prelude::*;
use std::process::Command;

fn cmd() -> Command {
    Command::cargo_bin("realm-measurements").unwrap()
}

#[test]
fn no_param() {
    // Without argument, shows the usage an aborts
    let result = cmd().assert();
    result.failure().stderr(predicate::str::contains("Usage:"));

    let result = cmd().arg("help").assert();
    result.success().stdout(predicate::str::contains("Usage:"));
}

#[test]
fn kvmtool_params() {
    cmd()
        .args(["kvmtool", "--realm"])
        .assert()
        .failure()
        .append_context("test", "missing CPUs")
        .stderr("ERROR Cannot build parameters: number of vCPUs is not known\n");

    cmd()
        .args(["kvmtool", "--realm", "-c", "1"])
        .assert()
        .append_context("args", "missing RAM size")
        .failure()
        .stderr("ERROR Cannot build parameters: default guest RAM size is not known\n");

    cmd()
        .args(["kvmtool", "--realm", "-c", "1", "-m", "512M"])
        .assert()
        .append_context("test", "missing WPS")
        .failure()
        .stderr("ERROR Failed to compute measurements: num_wps is not known\n");

    let args = ["--num-wps", "6", "--num-bps", "6", "kvmtool"];

    cmd()
        .args(args)
        .args(["--realm", "-c", "1", "-m", "512M"])
        .assert()
        .append_context("test", "minimum working kvmtool cmdline")
        .success()
        .stdout(predicate::str::contains(
            "998dfdf6401d69f73ed88ac53d62d5ea2cfac6320b887ce4599aa8671791d4d",
        ));

    // We accept and ignore these parameters. Not exhaustive.
    cmd()
        .args(args)
        .args([
            "--realm",
            "-c",
            "1",
            "-m",
            "512M",
            "--debug",
            "--debug-single-step",
            "--debug-mmio",
            "--force-pci",
            "--no-pvtime",
            "--vcpu-affinity",
            "AFF",
            "--disable-mte",
        ])
        .assert()
        .append_context("test", "ignored params")
        .success()
        .stdout(predicate::str::contains(
            "998dfdf6401d69f73ed88ac53d62d5ea2cfac6320b887ce4599aa8671791d4d",
        ));
}

#[test]
fn kvmtool_measurements() {
    let tmp_dir = assert_fs::TempDir::new().unwrap();
    let fw_file = tmp_dir.child("firmware");

    fw_file.write_binary(b"FW CONTENT").unwrap();

    // Test --print-b64 while at it
    let args = [
        "--num-wps",
        "6",
        "--num-bps",
        "6",
        "-f",
        fw_file.to_str().unwrap(),
        "kvmtool",
    ];

    cmd()
        .args(args)
        .args([
            "--realm",
            "--firmware",
            "firmware",
            "-c",
            "1",
            "-m",
            "512M",
        ])
        .assert()
        .append_context("test", "measure firmware")
        .success()
        .stdout("RIM: cf37146fce0ad50e1be1a04580c1024e5449b430b0dd96b6ef5c9a2b73767bf50000000000000000000000000000000000000000000000000000000000000000
REM0: 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
REM1: 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
REM2: 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
REM3: 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
");

    // Test --print-b64 while at it
    let args = [
        "--num-wps",
        "6",
        "--num-bps",
        "6",
        "-f",
        fw_file.to_str().unwrap(),
        "--print-b64",
        "kvmtool",
    ];

    cmd()
        .args(args)
        .args([
            "--realm",
            "--firmware",
            "firmware",
            "-c",
            "1",
            "-m",
            "512M",
        ])
        .assert()
        .append_context("test", "measure firmware (base 64)")
        .success()
        .stdout("RIM: zzcUb84K1Q4b4aBFgMECTlRJtDCw3Za271yaK3N2e/UAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
REM0: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
REM1: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
REM2: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
REM3: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
");

    tmp_dir.close().unwrap();
}

#[test]
fn qemu_params() {
    let args = [
        "--num-wps",
        "6",
        "--num-bps",
        "6",
        "--ipa-bits",
        "52",
        "qemu",
    ];

    // No arguments (invalid in QEMU but accepted by our tool)
    cmd()
        .args(args)
        .assert()
        .append_context("test", "no arguments")
        .success()
        .stdout(predicate::str::contains("RIM: cf409055d866eea6c8d5e7862b540ff1cac9b11f125d088587d5ae97a0e3341667cf8fb3983e7377bca5c01d037bd97081ebf3b4dcb648442149749f4d65eeb0"));

    // GIC version: 2 is unsupported
    cmd()
        .args(args)
        .args(["-M", "virt,gic-version=2"])
        .assert()
        .append_context("test", "GICv2")
        .failure()
        .stderr("ERROR Cannot build parameters: unsupport GIC version 2\n");
    cmd()
        .args(args)
        .args(["-M", "virt,gic-version=4"])
        .assert()
        .append_context("test", "GICv4")
        .failure();

    // GIC version: host is supported, an alias for "3"
    cmd()
        .args(args)
        .args(["-M", "virt,gic-version=host"])
        .assert()
        .append_context("test", "GIC host")
        .success()
        .stderr("");
    cmd()
        .args(args)
        .args(["-M", "virt,gic-version=max"])
        .assert()
        .append_context("test", "GIC max")
        .success()
        .stderr("");
    cmd()
        .args(args)
        .args(["-M", "virt,gic-version=3"])
        .assert()
        .append_context("test", "GICv3")
        .success()
        .stderr("");
}
