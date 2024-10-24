/// Initialize Realm parameters for the QEMU virt machine
//
// For simplicity we assume that the user input will successfully boot a Realm
// VM, so we don't thoroughly check the validity of each parameter. QEMU will do
// that.
use std::cmp::{max, min};

use anyhow::{bail, Context, Result};

use crate::command_line::*;
use crate::fdt::*;
use crate::realm_config::*;
use crate::utils::*;
use crate::vmm::*;

const QEMU_GIC_DIST_BASE: u64 = 0x08000000;
const QEMU_GIC_DIST_SIZE: u64 = 0x00010000;
const QEMU_GIC_ITS_BASE: u64 = 0x08080000;
const QEMU_GIC_ITS_SIZE: u64 = 0x00020000;
const QEMU_GIC_REDIST_BASE: u64 = 0x080a0000;
const QEMU_GIC_REDIST_SIZE: u64 = 0x00f60000;
const QEMU_UART_BASE: u64 = 0x09000000;
const QEMU_UART_SIZE: u64 = 0x00001000;
const QEMU_RTC_BASE: u64 = 0x09010000;
const QEMU_RTC_SIZE: u64 = 0x00001000;
const QEMU_FW_CFG_BASE: u64 = 0x09020000;
const QEMU_FW_CFG_SIZE: u64 = 0x00000018;
const QEMU_VIRTIO_MMIO_BASE: u64 = 0x0a000000;
const QEMU_VIRTIO_MMIO_SIZE: u64 = 0x00000200; // one device
const QEMU_PLATFORM_BUS_BASE: u64 = 0x0c000000;
const QEMU_PLATFORM_BUS_SIZE: u64 = 0x02000000;
const QEMU_PCI_MMIO_BASE: u64 = 0x10000000;
const QEMU_PCI_MMIO_SIZE: u64 = 0x2eff0000;
const QEMU_PCI_IOPORT_BASE: u64 = 0x3eff0000;
const QEMU_PCI_IOPORT_SIZE: u64 = 0x00010000;
const QEMU_MEM_BASE: u64 = 0x40000000;
const QEMU_HIGH_REDIST_BASE: u64 = 0x40_00000000;
const QEMU_HIGH_REDIST_SIZE: u64 = 64 * MIB;
const QEMU_HIGH_PCI_CFG_BASE: u64 = 0x40_10000000;
const QEMU_HIGH_PCI_CFG_SIZE: u64 = 256 * MIB;
const QEMU_HIGH_PCI_MMIO_BASE: u64 = 0x80_00000000;
const QEMU_HIGH_PCI_MMIO_SIZE: u64 = 512 * GIB;

const QEMU_SPI_UART: u32 = 1;
const QEMU_SPI_RTC: u32 = 2;
const QEMU_SPI_PCIE: u32 = 3;
const QEMU_SPI_MMIO: u32 = 16;

const QEMU_PPI_PMU: u32 = 7;

const QEMU_DTB_SIZE: u64 = 1024 * KIB;
const QEMU_LOG_SIZE: u64 = 64 * KIB;

/// QEMU configuration
#[derive(Default)]
pub struct QemuParams {
    num_cpus: usize,
    mem_size: u64,
    // Kernel command line
    bootargs: Option<String>,
    // Guest address
    kernel_start: u64,
    initrd: Option<(u64, u64)>,
    log: Option<(u64, u64)>,
    has_pmu: bool,
    has_its: bool,
    has_acpi: bool,
    has_measurement_log: bool,
    gic_version: GicModel,
}

impl QemuParams {
    /// Create a new QemuParams instance
    pub fn new() -> Self {
        Self {
            num_cpus: 1,
            mem_size: 128 * MIB,
            // On recent virt machines, ITS is enabled by default
            has_its: true,
            has_acpi: true,
            gic_version: GicModel::GICv3,
            ..Default::default()
        }
    }
}

/// Command-line arguments for QEMU
#[derive(Debug, clap::Args)]
pub struct QemuArgs {
    /// Arguments passed to QEMU
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

fn parse_bool(dest: &mut bool, val: &str) -> Result<()> {
    match val {
        "on" => *dest = true,
        "off" => *dest = false,
        "auto" => (),
        _ => bail!("expected on/off/auto, got '{val}'"),
    }
    Ok(())
}

// Parse -m argument, return the memory size in bytes
fn parse_mem(raw_args: &mut RawArgs) -> Result<u64> {
    let arg = pop_arg(raw_args, "-m")?;

    let mut size_str = "";
    for item in arg.split(',') {
        let Some((prop, val)) = item.split_once('=') else {
            size_str = item;
            continue;
        };

        match prop {
            "size" => size_str = val,
            _ => bail!("unsupported -m parameter {prop}"),
        }
    }

    parse_memory_size(size_str).context("-m")
}

// Parse -smp argument, return number of vCPUs
fn parse_smp(raw_args: &mut RawArgs) -> Result<usize> {
    let arg = pop_arg(raw_args, "-smp")?;

    let mut cpus_str = "";
    for item in arg.split(',') {
        let Some((prop, val)) = item.split_once('=') else {
            cpus_str = item;
            continue;
        };

        match prop {
            "cpus" => cpus_str = val,
            _ => bail!("unsupported -smp parameter {prop}"),
        }
    }

    let cpus: usize = cpus_str.parse().context("-smp")?;
    Ok(cpus)
}

// Parse rme-guest object
fn parse_object(
    raw_args: &mut RawArgs,
    realm: &mut RealmConfig,
    qemu: &mut QemuParams,
) -> Result<()> {
    let arg = pop_arg(raw_args, "-object")?;
    let mut items = arg.split(',');

    let Some(obj_type) = items.next() else {
        return Ok(());
    };
    if obj_type != "rme-guest" {
        log::warn!("ignored -object {obj_type}");
        return Ok(());
    }

    for item in items {
        let Some((prop, val)) = item.split_once('=') else {
            bail!("cannot parse {item}");
        };

        match prop {
            "measurement-algo" => realm.set_measurement_algo(val)?,
            "personalization-value" => realm.personalization_value.parse(val)?,
            "measurement-log" => qemu.has_measurement_log = true,
            "id" => (),
            _ => bail!("unsupported rme-guest property '{prop}'"),
        }
    }

    Ok(())
}

// Parse -M/-machine options
fn parse_machine(raw_args: &mut RawArgs, qemu: &mut QemuParams) -> Result<()> {
    let arg = pop_arg(raw_args, "-machine")?;

    for item in arg.split(',') {
        let Some((prop, val)) = item.split_once('=') else {
            if item == "virt" {
                continue;
            }
            // Setting bools without '=on' is deprecated, let's not support it.
            bail!("cannot parse {item}");
        };

        match prop {
            "gic-version" => {
                qemu.gic_version = match val {
                    "3" => GicModel::GICv3,
                    "4" => GicModel::GICv4,
                    _ => bail!("unsupport GIC version {val}"),
                }
            }
            "its" => parse_bool(&mut qemu.has_its, val)?,
            "acpi" => parse_bool(&mut qemu.has_acpi, val)?,
            "highmem" => bail!("disabling highmem is not supported"),
            "confidential-guest-support" => (),
            _ => log::warn!("ignored machine parameter {prop}"),
        }
    }
    Ok(())
}

fn parse_cpu(raw_args: &mut RawArgs, realm: &mut RealmConfig) -> Result<()> {
    let arg = pop_arg(raw_args, "-cpu")?;

    // Keep the the default SVE VL.
    let mut sve_vl = realm.params.sve_vl;

    for item in arg.split(',') {
        let Some((prop, val)) = item.split_once('=') else {
            if item == "host" {
                continue;
            }
            bail!("unsupported CPU {item}");
        };

        match prop {
            "num-breakpoints" => realm.params.restrict_num_bps(val.parse()?)?,
            "num-watchpoints" => realm.params.restrict_num_wps(val.parse()?)?,
            "num-pmu-counters" => realm.params.restrict_pmu_num_ctrs(val.parse()?)?,
            "sve" => {
                if val == "off" {
                    sve_vl = Some(0);
                }
            }
            p if p.starts_with("sve") => {
                // Parse sve<vl>=on/off, roughly.
                let vl: u16 = p[3..].parse()?;
                let cur_vl = sve_vl.unwrap_or(0);
                if val == "off" && cur_vl >= vl {
                    // Disabling a VL leaves the lower VL enabled.
                    sve_vl = Some(vl / 2);
                } else if val == "on" && cur_vl < vl {
                    sve_vl = Some(vl)
                }
            }
            _ => log::warn!("ignored cpu parameter {prop}"),
        }
    }
    if let Some(v) = sve_vl {
        realm.params.restrict_sve_vl(v)?;
    }

    Ok(())
}

fn parse_append(raw_args: &mut RawArgs, qemu: &mut QemuParams) -> Result<()> {
    let val = pop_arg(raw_args, "-append")?;
    qemu.set_bootargs(&val);
    Ok(())
}

fn parse_ignore(raw_args: &mut RawArgs, arg: &str) -> Result<()> {
    let val = pop_arg(raw_args, arg)?;
    log::warn!("ignored {arg} {val}");
    Ok(())
}

impl DTBGenerator for QemuParams {
    fn set_initrd(&mut self, base: GuestAddress, size: u64) {
        self.initrd = Some((base, size));
    }

    fn set_log_location(&mut self, base: GuestAddress, size: u64) {
        self.log = Some((base, size));
    }

    fn set_mem_size(&mut self, mem_size: u64) {
        self.mem_size = mem_size;
    }

    fn set_num_cpus(&mut self, num_cpus: usize) {
        self.num_cpus = num_cpus;
    }

    fn set_pmu(&mut self, pmu: bool) {
        self.has_pmu = pmu;
    }

    fn set_its(&mut self, its: bool) {
        self.has_its = its;
    }

    fn set_bootargs(&mut self, bootargs: &str) {
        self.bootargs = Some(bootargs.to_string());
    }

    /// Generate a DTB for the virt machine, and add it as a blob
    ///
    /// This is currently based on QEMU virt 9.1
    ///
    fn gen_dtb(&self) -> VmmResult<Vec<u8>> {
        let gic_phandle: u32 = 1;
        let its_phandle: u32 = 2;
        let clock_phandle: u32 = 3;

        let (mut fdt, root_node) = fdt_new(
            (QEMU_MEM_BASE, self.mem_size),
            self.num_cpus,
            gic_phandle,
            self.bootargs.as_deref(),
            self.initrd,
        )?;

        let bus_node =
            fdt_begin_node_addr(&mut fdt, "platform-bus", QEMU_PLATFORM_BUS_BASE)?;
        fdt.property_u32("interrupt-parent", gic_phandle)?;
        fdt.property_array_u32(
            "ranges",
            &[0, 0, lo(QEMU_PLATFORM_BUS_BASE), lo(QEMU_PLATFORM_BUS_SIZE)],
        )?;
        fdt.property_u32("#address-cells", 1)?;
        fdt.property_u32("#size-cells", 1)?;
        let compat = vec!["self,platform".to_string(), "simple-bus".to_string()];
        fdt.property_string_list("compatible", compat)?;
        fdt.end_node(bus_node)?;

        if let Some((log_base, log_size)) = self.log {
            // Add a node for the measurement log within reserved-memory
            let resv_mem_node = fdt.begin_node("reserved-memory")?;
            fdt.property_u32("#address-cells", 2)?;
            fdt.property_u32("#size-cells", 2)?;
            fdt.property_null("ranges")?;
            let log_node = fdt_begin_node_addr(&mut fdt, "event-log", log_base)?;
            fdt.property_string("compatible", "cc-event-log")?;
            fdt.property_array_u64("reg", &[log_base, log_size])?;

            fdt.end_node(log_node)?;
            fdt.end_node(resv_mem_node)?;
        }

        let fw_cfg_node = fdt_begin_node_addr(&mut fdt, "fw-cfg", QEMU_FW_CFG_BASE)?;
        fdt.property_null("dma-coherent")?;
        fdt.property_array_u64("reg", &[QEMU_FW_CFG_BASE, QEMU_FW_CFG_SIZE])?;
        fdt.property_string("compatible", "self,fw-cfg-mmio")?;
        fdt.end_node(fw_cfg_node)?;

        for i in 0..32 {
            let addr: u64 = QEMU_VIRTIO_MMIO_BASE + i * QEMU_VIRTIO_MMIO_SIZE;
            let interrupt: u32 = QEMU_SPI_MMIO + i as u32;
            let virtio_mmio_node = fdt_begin_node_addr(&mut fdt, "virtio_mmio", addr)?;
            fdt.property_null("dma-coherent")?;
            let interrupts = [FDT_IRQ_SPI, interrupt, FDT_IRQ_EDGE_LO_HI];
            fdt.property_array_u32("interrupts", &interrupts)?;
            fdt.property_array_u64("reg", &[addr, QEMU_VIRTIO_MMIO_SIZE])?;
            fdt.property_string("compatible", "virtio,mmio")?;
            fdt.end_node(virtio_mmio_node)?;
        }

        let pcie_node = fdt_begin_node_addr(&mut fdt, "pcie", QEMU_HIGH_PCI_CFG_BASE)?;
        // Generate interrupt-map
        let mut irq_map: Vec<u32> = vec![];
        for dev in 0..4 {
            for pin in 0..4 {
                let irq_nr = QEMU_SPI_PCIE + ((pin + dev) % 4);
                irq_map.extend_from_slice(&[
                    (pci_devfn(dev as u8, 0) as u32) << 8,
                    0,
                    0,
                    pin + 1,
                    gic_phandle,
                    0,
                    0,
                    FDT_IRQ_SPI,
                    irq_nr,
                    FDT_IRQ_LEVEL_HI,
                ]);
            }
        }
        fdt.property_array_u32("interrupt-map", &irq_map)?;
        // All PCI devices share four IRQ lines
        let devfn_mask = pci_devfn(0x3, 0) as u32;
        fdt.property_array_u32("interrupt-map-mask", &[devfn_mask << 8, 0, 0, 0x7])?;
        fdt.property_u32("#interrupt-cells", 1)?;
        fdt.property_array_u32(
            "ranges",
            &[
                FDT_PCI_RANGE_IOPORT,
                0,
                0,
                0,
                lo(QEMU_PCI_IOPORT_BASE),
                0,
                lo(QEMU_PCI_IOPORT_SIZE),
                FDT_PCI_RANGE_MMIO,
                0,
                lo(QEMU_PCI_MMIO_BASE),
                0,
                lo(QEMU_PCI_MMIO_BASE),
                0,
                lo(QEMU_PCI_MMIO_SIZE),
                FDT_PCI_RANGE_MMIO_64BIT,
                hi(QEMU_HIGH_PCI_MMIO_BASE),
                lo(QEMU_HIGH_PCI_MMIO_BASE),
                hi(QEMU_HIGH_PCI_MMIO_BASE),
                lo(QEMU_HIGH_PCI_MMIO_BASE),
                hi(QEMU_HIGH_PCI_MMIO_SIZE),
                lo(QEMU_HIGH_PCI_MMIO_SIZE),
            ],
        )?;

        fdt.property_array_u64("reg", &[QEMU_HIGH_PCI_CFG_BASE, QEMU_HIGH_PCI_CFG_SIZE])?;
        if self.has_its {
            fdt.property_array_u32("msi-map", &[0, its_phandle, 0, 0x10000])?;
        }
        fdt.property_null("dma-coherent")?;
        fdt.property_array_u32("bus-range", &[0, 0xff])?;
        fdt.property_u32("linux,pci-domain", 0)?;
        fdt.property_u32("#size-cells", 2)?;
        fdt.property_u32("#address-cells", 3)?;
        fdt.property_string("device_type", "pci")?;
        fdt.property_string("compatible", "pci-host-ecam-generic")?;
        fdt.end_node(pcie_node)?;

        let rtc_node = fdt_begin_node_addr(&mut fdt, "pl031", QEMU_RTC_BASE)?;
        fdt.property_string("clock-names", "apb_pclk")?;
        fdt.property_array_u64("reg", &[QEMU_RTC_BASE, QEMU_RTC_SIZE])?;
        fdt.property_u32("clocks", clock_phandle)?;
        let interrupts = [FDT_IRQ_SPI, QEMU_SPI_RTC, FDT_IRQ_LEVEL_HI];
        fdt.property_array_u32("interrupts", &interrupts)?;
        fdt.property_string_list(
            "compatible",
            vec!["arm,pl031".to_string(), "arm,primecell".to_string()],
        )?;
        fdt.end_node(rtc_node)?;

        let uart_node = fdt_begin_node_addr(&mut fdt, "pl011", QEMU_UART_BASE)?;
        fdt.property_string_list(
            "clock-names",
            vec!["uartclk".to_string(), "apb_pclk".to_string()],
        )?;
        fdt.property_array_u64("reg", &[QEMU_UART_BASE, QEMU_UART_SIZE])?;
        fdt.property_array_u32("clocks", &[clock_phandle, clock_phandle])?;
        fdt.property_array_u32(
            "interrupts",
            &[FDT_IRQ_SPI, QEMU_SPI_UART, FDT_IRQ_LEVEL_HI],
        )?;
        fdt.property_string_list(
            "compatible",
            vec!["arm,pl011".to_string(), "arm,primecell".to_string()],
        )?;
        fdt.end_node(uart_node)?;

        if self.has_pmu {
            fdt_add_pmu(&mut fdt, QEMU_PPI_PMU)?;
        }

        let mut gic_regs = vec![
            QEMU_GIC_DIST_BASE,
            QEMU_GIC_DIST_SIZE,
            QEMU_GIC_REDIST_BASE,
            QEMU_GIC_REDIST_SIZE,
        ];

        let redist_size = match self.gic_version {
            GicModel::GICv3 => 0x20000,
            GicModel::GICv4 => 0x40000,
        };
        if self.num_cpus > QEMU_GIC_REDIST_SIZE as usize / redist_size {
            gic_regs.push(QEMU_HIGH_REDIST_BASE);
            gic_regs.push(QEMU_HIGH_REDIST_SIZE)
        }

        let its_reg = if self.has_its {
            Some([QEMU_GIC_ITS_BASE, QEMU_GIC_ITS_SIZE])
        } else {
            None
        };
        fdt_add_gic(&mut fdt, &gic_regs, its_reg, gic_phandle, its_phandle)?;
        fdt_add_timer(&mut fdt, &[13, 14, 11], FDT_IRQ_LEVEL_HI)?;

        let clk_node = fdt.begin_node("apb-pclk")?;
        fdt.property_phandle(clock_phandle)?;
        fdt.property_string("clock-output-names", "clk24mhz")?;
        fdt.property_u32("clock-frequency", 24000000)?;
        fdt.property_u32("#clock-cells", 0)?;
        fdt.property_string("compatible", "fixed-clock")?;
        fdt.end_node(clk_node)?;

        fdt.end_node(root_node)?;
        Ok(fdt.finish()?)
    }
}

fn check_memmap(realm: &mut RealmConfig, qemu: &mut QemuParams) -> Result<()> {
    let Some(ipa_bits) = realm.params.ipa_bits else {
        bail!("max IPA size is not known");
    };
    if ipa_bits < 41 {
        bail!("the VM needs at least 41 IPA bits to fit the memory map");
    }

    // Memory hotplug is not supported at the moment, not is variable memory map.
    if qemu.mem_size > 255 * GIB {
        bail!("no more than 255GB of RAM is supported");
    }

    // The high PCI regions require 40 IPA bits, and we reserve one more for NS
    // memory
    realm.params.restrict_ipa_bits(41)?;
    Ok(())
}

/// Create a [RealmConfig] from the QEMU command-line.
pub fn build_params(args: &Args, qemu_args: &QemuArgs) -> Result<RealmConfig> {
    let mut use_firmware = false;
    let mut use_kernel = false;
    let mut use_initrd = false;
    let mut dtb_start = QEMU_MEM_BASE;
    let raw_args = &mut raw_args_from_vec(&qemu_args.args);

    let mut realm = RealmConfig::from_args(args)?;
    let mut qemu = QemuParams::new();

    realm.set_measurement_algo("sha512")?;
    qemu.set_pmu(realm.params.pmu.is_some_and(|v| v));

    // Parse QEMU's command-line to get more details about the desired VM
    while let Some(arg) = raw_args.pop_front() {
        let arg = split_arg_eq(raw_args, &arg);

        match arg.as_str() {
            "-m" => qemu.set_mem_size(parse_mem(raw_args)?),
            "-smp" => qemu.set_num_cpus(parse_smp(raw_args)?),
            "-object" => parse_object(raw_args, &mut realm, &mut qemu)?,
            "-append" => parse_append(raw_args, &mut qemu)?,
            "-machine" | "-M" => parse_machine(raw_args, &mut qemu)?,
            "-cpu" => parse_cpu(raw_args, &mut realm)?,
            "-device" | "-drive" | "-fsdev" => parse_ignore(raw_args, &arg)?,
            // These don't affect the RIM
            "-enable-kvm" | "-nographic" => (),
            "-dtb" => {
                pop_arg(raw_args, &arg)?;
            }
            "-kernel" => {
                pop_arg(raw_args, &arg)?;
                use_kernel = true;
            }
            "-initrd" => {
                pop_arg(raw_args, &arg)?;
                use_initrd = true;
            }
            "-bios" => {
                pop_arg(raw_args, &arg)?;
                // TODO: -drive method as well?
                use_firmware = true;
            }
            _ => {
                log::warn!("Parameter {arg} ignored");
            }
        }
    }

    // Ensure the memory map fits within the requested parameters
    check_memmap(&mut realm, &mut qemu)?;

    realm.add_ram(QEMU_MEM_BASE, qemu.mem_size)?;

    // Now load the blobs. We support these scenarios:
    // (a) direct kernel boot without firmware
    // (b) direct kernel boot with firmware
    // (c) firmware-only boot

    if use_kernel {
        let Some(filename) = &args.kernel else {
            bail!("need kernel image");
        };

        let kernel =
            load_kernel(filename, QEMU_MEM_BASE).with_context(|| filename.to_string())?;
        let kernel_load_size = kernel.load_size.unwrap_or(kernel.size);

        qemu.kernel_start = kernel.guest_start;

        let mut initrd_start = QEMU_MEM_BASE + min(qemu.mem_size / 2, 128u64 * MIB);
        let mut initrd_size = 0;
        // Avoid overriding kernel
        initrd_start = max(initrd_start, qemu.kernel_start + kernel_load_size);
        initrd_start = align_up(initrd_start, 4 * KIB);

        // Without firmware, the VMM loads images into memory. Otherwise, it
        // passes them to the firmware via fw_cfg. TODO: what REM index?
        if use_firmware {
            realm.add_rem_blob(0, kernel)?;
        } else {
            realm.add_rim_blob(kernel)?;
        }

        if use_initrd {
            let Some(filename) = &args.initrd else {
                bail!("need initrd image");
            };

            let initrd = VmmBlob::from_file(filename, initrd_start)?;
            initrd_size = initrd.size;
            qemu.set_initrd(initrd_start, initrd_size);
            if use_firmware {
                realm.add_rem_blob(0, initrd)?;
            } else {
                realm.add_rim_blob(initrd)?;
            }
        }

        dtb_start = align_up(initrd_start + initrd_size, 2 * MIB);
    }

    if qemu.has_measurement_log {
        qemu.set_log_location(dtb_start + QEMU_DTB_SIZE, QEMU_LOG_SIZE);
    }

    if use_firmware {
        let Some(filename) = &args.firmware else {
            bail!("need firmware image");
        };

        let firmware = VmmBlob::from_file(filename, 0)?;
        realm.add_rim_blob(firmware)?;
    }

    let pc = if use_firmware { 0 } else { QEMU_MEM_BASE };
    realm.add_rec(pc, [dtb_start, 0, 0, 0, 0, 0, 0, 0])?;

    if let Some((log_base, log_size)) = qemu.log {
        realm.add_rim_unmeasured(log_base, log_size)?;
    }

    // Now generate a DTB...
    qemu.add_dtb(&args.output_dtb, dtb_start, &mut realm)
        .context("while generating DTB")?;

    Ok(realm)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_mem() {
        fn string_to_args(s: &str) -> RawArgs {
            raw_args_from_vec(&vec![String::from(s)])
        }

        let mut args = string_to_args("hello");
        let r = parse_mem(&mut args);
        assert!(r.is_err());

        let mut args = string_to_args("1");
        let r = parse_mem(&mut args).unwrap();
        assert_eq!(r, 1 * MIB);

        let mut args = string_to_args("512");
        let r = parse_mem(&mut args).unwrap();
        assert_eq!(r, 512 * MIB);

        let mut args = string_to_args("size=512M");
        let r = parse_mem(&mut args).unwrap();
        assert_eq!(r, 512 * MIB);

        let mut args = string_to_args("512G");
        let r = parse_mem(&mut args).unwrap();
        assert_eq!(r, 512 * GIB);

        let mut args = string_to_args("size=2");
        let r = parse_mem(&mut args).unwrap();
        assert_eq!(r, 2 * MIB);

        let mut args = string_to_args("size=2,slots=2");
        let r = parse_mem(&mut args);
        assert!(r.is_err());
    }
}
