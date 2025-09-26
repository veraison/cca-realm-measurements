/// Run the realm-measurements command with various parameters
use assert_cmd::prelude::*;
use assert_fs::prelude::*;
use predicates::prelude::*;
use std::path::PathBuf;
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
fn error_reports() {
    cmd()
        .args([
            "--num-wps",
            "6",
            "--num-bps",
            "6",
            "-f",
            "nonexistent-file",
            "qemu",
            "-bios",
            "FW",
        ])
        .assert()
        .append_context("test", "nonexistent file")
        .failure()
        .stderr("ERROR Failed to compute measurements: VMM: file nonexistent-file error: No such file or directory (os error 2)\n");
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
        "--pmu-num-ctrs",
        "6",
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

    // QEMU defaults to what KVM supports. Our platform (args) currently doesn't
    // support PMU. This should thus have the same measurement as above.
    cmd()
        .args(args)
        .args(["-cpu", "pmu=off"])
        .assert()
        .append_context("test", "pmu=off")
        .success()
        .stderr("") // no "ignored parameter" warning
        .stdout(predicate::str::contains("RIM: cf409055d866eea6c8d5e7862b540ff1cac9b11f125d088587d5ae97a0e3341667cf8fb3983e7377bca5c01d037bd97081ebf3b4dcb648442149749f4d65eeb0"));

    cmd()
        .args(args)
        .args(["-cpu", "pmu=on"])
        .assert()
        .append_context("test", "pmu=on")
        .success()
        .stderr("")
        .stdout(predicate::str::contains("RIM: 8120ef921a987a3f8b9d4bb5e40f8489e2b4fc69c5e1b17b1a9b040884a1211d99b2bddc3fddcc99ec99f4244743fe3dcd3d9020583b47f7b66a2ec66bb897b9"));

    cmd()
        .args(["--pmu", "true"])
        .args(args)
        .args(["-cpu", "pmu=off"])
        .assert()
        .append_context("test", "pmu=off with platform on")
        .success()
        .stderr("")
        .stdout(predicate::str::contains("RIM: cf409055d866eea6c8d5e7862b540ff1cac9b11f125d088587d5ae97a0e3341667cf8fb3983e7377bca5c01d037bd97081ebf3b4dcb648442149749f4d65eeb0"));

    cmd()
        .args(args)
        .args(["-cpu", "pmu=on,num-pmu-counters=2"])
        .assert()
        .append_context("test", "pmu=on num-counters")
        .success()
        .stderr("")
        .stdout(predicate::str::contains("RIM: ef4e6f78ea9630f66146b33a405a07b669ef94dd9aca6935d4fd23fea32f98f964241a2f9a9c20c9fcd74e20031c51c4beb8e577873e0348e891ee2d727e2807"));
}

#[test]
fn qemu_measurements() {
    let tmp_dir = assert_fs::TempDir::new().unwrap();
    let fw_file = tmp_dir.child("firmware");
    // We need a file with a valid kernel header
    let kernel_path: PathBuf = [
        std::env::var("CARGO_MANIFEST_DIR").unwrap().as_str(),
        "testdata",
        "linux.bin",
    ]
    .iter()
    .collect();
    let initrd_file = tmp_dir.child("initrd");

    fw_file.write_binary(b"FW CONTENT").unwrap();
    initrd_file.write_binary(b"INITRD CONTENT").unwrap();

    let args = [
        "--num-wps",
        "6",
        "--num-bps",
        "6",
        "--ipa-bits",
        "52",
        "--pmu-num-ctrs",
        "6",
        "-f",
        fw_file.to_str().unwrap(),
        "-k",
        &kernel_path.to_string_lossy(),
        "-i",
        initrd_file.to_str().unwrap(),
        "qemu",
        "-M",
        "confidential-guest-support=rme0",
        "-object",
        "rme-guest,id=rme0,measurement-algorithm=sha256",
        "-cpu",
        "host",
        "-M",
        "virt",
        "-enable-kvm",
        "-smp",
        "2",
        "-m",
        "1G",
        "-nographic",
    ];

    cmd()
        .args(args)
        .args(["-bios", "firmware"])
        .assert()
        .append_context("test", "measure firmware")
        .success()
        .stderr("")
        .stdout(predicate::str::contains(
            "RIM: cbf533a94009dfa6b83016a89b428d1d910fb3593856bb386d7b2bd07a1bc834",
        ));

    // With -bios the kernel is passed at runtime via fw_cfg
    cmd()
        .args(args)
        .args(["-bios", "firmware", "-kernel", "Image"])
        .assert()
        .append_context("test", "measure firmware with -kernel")
        .success()
        .stderr("")
        .stdout(predicate::str::contains(
            "RIM: cbf533a94009dfa6b83016a89b428d1d910fb3593856bb386d7b2bd07a1bc834",
        ));

    // With -bios and -append, the command-line is passed via fw_cfg, but also
    // in the DTB (hence the different RIM)
    cmd()
        .args(args)
        .args([
            "-bios",
            "firmware",
            "-kernel",
            "Image",
            "-append",
            "root=/dev/vda2",
        ])
        .assert()
        .append_context("test", "measure firmware with -append")
        .success()
        .stderr("")
        .stdout(predicate::str::contains(
            "RIM: fd3ce1072c3e95cd3a4d1a07729756564f260f9f7e95014418b416673a268b7a",
        ));

    // No -bios, the kernel gets measured into the RIM
    cmd()
        .args(args)
        .args(["-kernel", "Image"])
        .assert()
        .append_context("test", "measure kernel")
        .success()
        .stderr("")
        .stdout(predicate::str::contains(
            "RIM: e8862e21b8eb6b4bdeeff244dc59d2935c26d92c52d346f06e224fe712267a6",
        ));

    cmd()
        .args(args)
        .args(["-kernel", "Image", "-initrd", "initrd"])
        .assert()
        .append_context("test", "measure kernel + initrd")
        .success()
        .stderr("")
        .stdout(predicate::str::contains(
            "RIM: 9af47a8e4d6ac775e05f8a8893f9e383694688719d1bbb4281ed1c25056e0911",
        ));

    cmd()
        .args(args)
        .args([
            "-kernel",
            "Image",
            "-initrd",
            "initrd",
            "-append",
            "root=/dev/vda2",
        ])
        .assert()
        .append_context("test", "measure kernel + initrd + cmdline")
        .success()
        .stderr("")
        .stdout(predicate::str::contains(
            "RIM: 22d398e695e776385bc268454587b418dde16e34bc69d9a24fc96abb3050a24e",
        ));
}

#[test]
fn qemu_dtb() {
    let tmp_dir = assert_fs::TempDir::new().unwrap();
    let fw_file = tmp_dir.child("firmware");
    let dtb_file = tmp_dir.child("dtb");
    let output_dtb_file = tmp_dir.child("output.dtb");

    fw_file.write_binary(b"FW CONTENT").unwrap();

    let args = [
        "--num-wps",
        "6",
        "--num-bps",
        "6",
        "--ipa-bits",
        "52",
        "--pmu-num-ctrs",
        "6",
        "-f",
        fw_file.to_str().unwrap(),
        "qemu",
    ];

    output_dtb_file.assert(predicate::path::missing());

    cmd()
        .args(["--output-dtb", output_dtb_file.to_str().unwrap()])
        .args(args)
        .args([
            "-M",
            "confidential-guest-support=rme0",
            "-object",
            "rme-guest,id=rme0,measurement-algorithm=sha512",
            "-cpu",
            "host",
            "-M",
            "virt",
            "-enable-kvm",
            "-smp",
            "2",
            "-m",
            "1G",
            "-nographic",
            "-dtb",
            "output.dtb",
            "-bios",
            "firmware",
        ])
        .assert()
        .append_context("test", "generate dtb")
        .success()
        .stderr("")
        .stdout(predicate::str::contains("RIM: 3175b3c0c201081ad410defe6c32e145fd77ff03e63518a9f00831b12b6ec2070f743f43f0ff3290902ecebd4e6bea8d5926dca19dc1a06fb8d51d551a4a2b79"));

    output_dtb_file.assert(predicate::path::is_file());

    dtb_file.write_file(&output_dtb_file).unwrap();
    std::fs::remove_file(&output_dtb_file).unwrap();
    output_dtb_file.assert(predicate::path::missing());
    dtb_file.assert(predicate::path::is_file());

    // Check that --dtb is output as is, and no DTB generation or patching takes
    // place.
    cmd()
        .args(["--dtb", dtb_file.to_str().unwrap(), "--output-dtb", output_dtb_file.to_str().unwrap()])
        .args(args)
        .args([
            "-M",
            "confidential-guest-support=rme0",
            "-object",
            "rme-guest,id=rme0,measurement-algorithm=sha512",
            "-cpu",
            "host",
            "-M",
            "virt",
            "-enable-kvm",
            "-smp", // different SMP parameter would change output DTB,
            "8",    // but we passed a fixed DTB with --dtb
            "-m",
            "1G",
            "-nographic",
            "-dtb",
            "output.dtb",
            "-bios",
            "firmware",
        ])
        .assert()
        .append_context("test", "input exact dtb")
        .success()
        .stderr("")
        .stdout(predicate::str::contains("RIM: 3175b3c0c201081ad410defe6c32e145fd77ff03e63518a9f00831b12b6ec2070f743f43f0ff3290902ecebd4e6bea8d5926dca19dc1a06fb8d51d551a4a2b79"));

    output_dtb_file.assert(predicate::path::eq_file(dtb_file.to_str().unwrap()));

    std::fs::remove_file(&output_dtb_file).unwrap();
    output_dtb_file.assert(predicate::path::missing());

    // --input-dtb doesn't exist anymore
    cmd()
        .args(["--input-dtb", dtb_file.to_str().unwrap()])
        .args(args)
        .assert()
        .append_context("test", "--input-dtb doesn't exist")
        .failure()
        .stderr(predicate::str::contains("error: unexpected argument"));

    // --dtb or --dtb-template but not both
    cmd()
        .args([
            "--dtb",
            dtb_file.to_str().unwrap(),
            "--dtb-template",
            dtb_file.to_str().unwrap(),
        ])
        .args(args)
        .assert()
        .append_context("test", "--dtb incompatible with --dtb-template")
        .failure()
        .stderr("ERROR Invalid arguments: either --dtb or --dtb-template can be set but not both\n");

    // it's now --dtb-template, which provides a base DTB to patch. Now the
    // output DTB should describe 8 CPUs.
    cmd()
        .args(["--dtb-template", dtb_file.to_str().unwrap(), "--output-dtb", output_dtb_file.to_str().unwrap()])
        .args(args)
        .args([
            "-M",
            "confidential-guest-support=rme0",
            "-object",
            "rme-guest,id=rme0,measurement-algorithm=sha512",
            "-cpu",
            "host",
            "-M",
            "virt",
            "-enable-kvm",
            "-smp",
            "8",
            "-m",
            "1G",
            "-nographic",
            "-dtb",
            "output.dtb",
            "-bios",
            "firmware",
        ])
        .assert()
        .append_context("test", "input template dtb")
        .success()
        .stderr("")
        .stdout(predicate::str::contains("RIM: 68308d30762b7aa26f749d512864c0e0ad112e9626b8bf1c5486efe32b94b8d8ce8d736089ebf0850a91fda5422852294b679795202ed429fd8512b20b000728"));

    tmp_dir.close().unwrap();
}
