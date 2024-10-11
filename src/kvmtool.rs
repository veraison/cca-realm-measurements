use std::cmp::{max, min};

use anyhow::{bail, Context, Result};

use crate::command_line::*;
use crate::fdt::*;
use crate::realm::*;
use crate::utils::*;
use crate::vmm::*;

const KVMTOOL_IOPORT_BASE: u64 = 0x00000000;
const KVMTOOL_IOPORT_SIZE: u64 = 0x00010000;
const KVMTOOL_UART_BASE: u64 = 0x01000000;
const KVMTOOL_UART_SIZE: u64 = 0x00000008; // one device
const KVMTOOL_UART_STRIDE: u64 = 0x00001000; // one device
const KVMTOOL_RTC_BASE: u64 = 0x01010000;
const KVMTOOL_RTC_SIZE: u64 = 0x00000002;
const KVMTOOL_VIRTIO_MMIO_BASE: u64 = 0x03000000;
const KVMTOOL_VIRTIO_MMIO_SIZE: u64 = 0x00000200; // one device
const KVMTOOL_PCI_BASE: u64 = 0x40000000;
const KVMTOOL_PCI_CFG_BASE: u64 = KVMTOOL_PCI_BASE;
const KVMTOOL_PCI_CFG_SIZE: u64 = 1 << 28;
const KVMTOOL_PCI_MMIO_BASE: u64 = KVMTOOL_PCI_CFG_BASE + KVMTOOL_PCI_CFG_SIZE;
const KVMTOOL_PCI_MMIO_SIZE: u64 = KVMTOOL_MEM_BASE - KVMTOOL_PCI_MMIO_BASE;
const KVMTOOL_GIC_DIST_BASE: u64 = 0x3fff0000;
const KVMTOOL_GIC_DIST_SIZE: u64 = 0x00010000;
const KVMTOOL_GIC_REDIST_SIZE: u64 = 0x20000;
const KVMTOOL_GIC_ITS_SIZE: u64 = 128 * KIB;
const KVMTOOL_MEM_BASE: u64 = 0x80000000;

const KVMTOOL_SPI_UART: u32 = 0;
const KVMTOOL_SPI_VIRTIO_MMIO: u32 = 4;
const KVMTOOL_SPI_PCI: u32 = 64;

const FDT_BASE: GuestAddress = KVMTOOL_MEM_BASE + (256 - 2) * MIB;
const FDT_ALIGN: GuestAddress = 2 * MIB;
const FDT_SIZE: usize = 0x10000;

// lkvm run arguments. Define anything that could be passed to kvmtool, even
// those we won't inspect ourself, so the arg parser doesn't complain. But don't
// define those we don't currently support, such as "aarch32".
#[derive(Debug, clap::Args)]
pub struct KvmtoolArgs {
    #[arg(long)]
    name: Option<String>,

    #[arg(short, long)]
    cpus: Option<usize>,

    #[arg(short, long)]
    mem: Option<String>,

    #[arg(short, long)]
    disk: Vec<String>,

    #[arg(long)]
    balloon: bool,

    #[arg(long)]
    rng: bool,

    #[arg(long)]
    nodefaults: bool,

    #[arg(long = "9p")]
    p9: Vec<String>,

    #[arg(long)]
    console: Option<String>,

    #[arg(long)]
    vsock: Option<u64>,

    #[arg(long)]
    dev: Option<String>,

    #[arg(long)]
    tty: Option<String>,

    #[arg(long)]
    hugetlbfs: Option<String>,

    #[arg(long)]
    virtio_transport: Option<String>,

    #[arg(long)]
    loglevel: Option<String>,

    #[arg(short, long)]
    kernel: Option<String>,

    #[arg(short, long)]
    initrd: Option<String>,

    #[arg(short, long)]
    params: Option<String>,

    #[arg(short, long)]
    firmware: Option<String>,

    #[arg(short = 'F', long)]
    flash: Option<String>,

    #[arg(short, long)]
    network: Vec<String>,

    #[arg(long)]
    no_dhcp: bool,

    #[arg(long)]
    vfio_pci: Vec<String>,

    #[arg(long)]
    debug: bool,

    #[arg(long)]
    debug_single_step: bool,

    #[arg(long)]
    debug_ioport: bool,

    #[arg(long)]
    debug_mmio: bool,

    #[arg(long)]
    debug_iodelay: Option<usize>,

    #[arg(long)]
    pmu: bool,

    #[arg(long)]
    disable_sve: bool,

    #[arg(long)]
    realm: bool,

    #[arg(long)]
    measurement_algo: Option<String>,

    #[arg(long)]
    realm_pv: Option<String>,

    #[arg(long)]
    sve_max_vl: Option<u16>,

    #[arg(long)]
    pmu_counters: Option<u8>,

    #[arg(long)]
    force_pci: bool,

    #[arg(long)]
    irqchip: Option<String>,

    #[arg(long)]
    firmware_address: Option<u64>,

    #[arg(long)]
    dtb: Option<String>,

    #[arg(long = "restricted_mem")]
    restricted_mem: bool,
}

#[derive(Default, PartialEq)]
enum VirtioTransport {
    #[default]
    Pci,
    Mmio,
}

enum DeviceType {
    Virtio,
}

#[derive(Default)]
struct KvmtoolParams {
    num_cpus: usize,
    mem_base: GuestAddress,
    mem_size: GuestAddress,
    dtb_base: GuestAddress,
    firmware_base: GuestAddress,
    initrd_base: GuestAddress,
    initrd_size: GuestAddress,
    use_kernel: bool,
    use_firmware: bool,
    has_its: bool,
    virtio_transport: VirtioTransport,
    virtio_mmio_devices: usize,
}

/// Parse "-m sz[@addr]" argument
fn parse_mem(arg: &Option<String>, kvmtool: &mut KvmtoolParams) -> Result<()> {
    let Some(arg) = arg else {
        // kvmtool picks a default size based on host memory, but we can't
        bail!("default guest RAM size is not known");
    };

    let mut items = arg.split('@');
    let Some(mem_str) = items.next() else {
        bail!("invalid mem");
    };

    kvmtool.mem_size = parse_memory_size(mem_str).context("-m")?;
    if !is_aligned(kvmtool.mem_size, 2 * MIB) {
        bail!("RAM size must be aligned on 2MB");
    }
    if items.next().is_some() {
        bail!("unsupported RAM base change");
    }

    Ok(())
}

fn add_device(kvmtool: &mut KvmtoolParams, devtype: DeviceType) {
    match devtype {
        DeviceType::Virtio => match kvmtool.virtio_transport {
            VirtioTransport::Pci => (),
            VirtioTransport::Mmio => kvmtool.virtio_mmio_devices += 1,
        },
    }
}

/// Parse one --network argument
fn parse_netdev(
    kvmtool: &mut KvmtoolParams,
    args: &str,
    count: &mut usize,
) -> Result<()> {
    for item in args.split(',') {
        let Some((name, val)) = item.split_once('=') else {
            bail!("malformed -n param {}", item);
        };

        match name {
            "mode" => {
                if val == "none" {
                    *count = 0; // disable default netdev
                } else {
                    *count += 1;
                }
            }
            "trans" => {
                let trans = match val {
                    "pci" => VirtioTransport::Pci,
                    "mmio" => VirtioTransport::Mmio,
                    _ => bail!("invalid transport {}", val),
                };
                if trans != kvmtool.virtio_transport {
                    // Do we need this?
                    bail!("unsupported virtio transport mismatch");
                }
            }
            _ => (),
        }
    }
    Ok(())
}

/// Parse all device related arguments
fn parse_device_cmdline(args: &KvmtoolArgs, kvmtool: &mut KvmtoolParams) -> Result<()> {
    use DeviceType::*;
    // Note that this depends on the host capabilities, but we assume it
    // supports ITS.
    kvmtool.has_its = true;
    if let Some(v) = &args.irqchip {
        match v.as_str() {
            "gicv3" => kvmtool.has_its = false,
            "gicv3-its" => (),
            _ => bail!("unsupported irqchip {}", v),
        }
    }

    if let Some(v) = &args.virtio_transport {
        kvmtool.virtio_transport = match v.as_str() {
            "pci" => VirtioTransport::Pci,
            "mmio" => VirtioTransport::Mmio,
            _ => bail!("unsupported virtio transport {}", v),
        }
    }

    // We can't predict the order in which virtio devices are instantiated.
    // That's alright because for the purpose of IRQ allocation and virtio-mmio
    // node generation, the specific device type doesn't make a difference.
    if args.balloon {
        add_device(kvmtool, Virtio);
    }
    if args.rng {
        add_device(kvmtool, Virtio);
    }
    for _ in &args.p9 {
        add_device(kvmtool, Virtio);
    }
    if args.vsock.is_some() {
        add_device(kvmtool, Virtio);
    }
    if let Some(v) = &args.console {
        if v == "virtio" {
            add_device(kvmtool, Virtio);
        }
    }
    for _ in &args.disk {
        add_device(kvmtool, Virtio);
    }
    let mut num_netdevs = 1; // one default netdev, unless user passes "mode=none"
    for netdev in &args.network {
        parse_netdev(kvmtool, netdev, &mut num_netdevs)?;
    }
    for _ in 0..num_netdevs {
        add_device(kvmtool, Virtio);
    }

    Ok(())
}

/// Parse arguments to lkvm run
fn parse_cmdline(
    args: &KvmtoolArgs,
    realm: &mut RealmConfig,
    kvmtool: &mut KvmtoolParams,
) -> Result<()> {
    if let Some(cpus) = args.cpus {
        kvmtool.num_cpus = cpus;
    } else {
        bail!("number of vCPUs is not known");
    }
    parse_mem(&args.mem, kvmtool)?;

    // Update realm params

    if let Some(v) = &args.measurement_algo {
        realm.set_measurement_algo(v)?;
    } else {
        realm.set_measurement_algo("sha256")?;
    }

    if args.pmu {
        realm.params.restrict_pmu(true);
    }

    if let Some(v) = args.pmu_counters {
        realm.params.restrict_pmu_num_ctrs(v)?;
    }

    if args.disable_sve {
        realm.params.restrict_sve_vl(0)?;
    } else if let Some(v) = args.sve_max_vl {
        realm.params.restrict_sve_vl(v)?;
    }

    if let Some(v) = &args.realm_pv {
        realm.personalization_value.copy(v)?;
    }

    let last_ipa = kvmtool.mem_base + kvmtool.mem_size - 1;
    let ipa_bits = max(last_ipa.ilog2() as u8, 32) + 1;
    realm.params.restrict_ipa_bits(ipa_bits)?;

    parse_device_cmdline(args, kvmtool)?;

    if let Some(v) = args.firmware_address {
        kvmtool.firmware_base = v;
    } else {
        kvmtool.firmware_base = kvmtool.mem_base;
    }

    Ok(())
}

/// Generate a DTB for the virt machine, and add it as a blob
fn add_dtb(
    args: &KvmtoolArgs,
    realm: &mut RealmConfig,
    kvmtool: &KvmtoolParams,
    output: &Option<String>,
) -> Result<()> {
    let gic_phandle: u32 = 1;
    let its_phandle: u32 = 2;

    let initrd = if kvmtool.initrd_size != 0 {
        Some((kvmtool.initrd_base, kvmtool.initrd_size))
    } else {
        None
    };

    let (mut fdt, root_node) = fdt_new(
        (kvmtool.mem_base, kvmtool.mem_size),
        kvmtool.num_cpus,
        gic_phandle,
        args.params.as_deref(),
        initrd,
    )?;

    let redist_size = (kvmtool.num_cpus as u64) * KVMTOOL_GIC_REDIST_SIZE;
    let redist_base = KVMTOOL_GIC_DIST_BASE - redist_size;

    let its_reg = if kvmtool.has_its {
        let its_size = KVMTOOL_GIC_ITS_SIZE;
        let its_base = redist_base - its_size;
        Some([its_base, its_size])
    } else {
        None
    };

    fdt_add_gic(
        &mut fdt,
        &[
            KVMTOOL_GIC_DIST_BASE,
            KVMTOOL_GIC_DIST_SIZE,
            redist_base,
            redist_size,
        ],
        its_reg,
        gic_phandle,
        its_phandle,
    )?;

    fdt_add_timer(&mut fdt, &[13, 14, 11], FDT_IRQ_LEVEL_LO)?;
    if realm.params.pmu.is_some_and(|v| v) {
        fdt_add_pmu(&mut fdt, 7)?;
    }

    let mut spi = KVMTOOL_SPI_UART;
    for i in 0..4 {
        let addr = KVMTOOL_UART_BASE + i as u64 * KVMTOOL_UART_STRIDE;
        let serial_node = fdt_begin_node_addr(&mut fdt, "U6_16550A", addr)?;
        fdt.property_string("compatible", "ns16550a")?;
        fdt.property_array_u64("reg", &[addr, KVMTOOL_UART_SIZE])?;
        fdt.property_array_u32("interrupts", &[FDT_IRQ_SPI, spi, FDT_IRQ_LEVEL_HI])?;
        fdt.property_u32("clock-frequency", 1843200)?;
        fdt.end_node(serial_node)?;
        spi += 1
    }

    spi = KVMTOOL_SPI_VIRTIO_MMIO;
    for i in 0..kvmtool.virtio_mmio_devices {
        let size = KVMTOOL_VIRTIO_MMIO_SIZE;
        let addr = KVMTOOL_VIRTIO_MMIO_BASE + i as u64 * size;
        let mmio_node = fdt_begin_node_addr(&mut fdt, "virtio", addr)?;
        fdt.property_string("compatible", "virtio,mmio")?;
        fdt.property_array_u64("reg", &[addr, size])?;
        fdt.property_null("dma-coherent")?;
        fdt.property_array_u32("interrupts", &[FDT_IRQ_SPI, spi, FDT_IRQ_EDGE_LO_HI])?;
        fdt.end_node(mmio_node)?;
        spi += 1;
    }

    let rtc_node = fdt_begin_node_addr(&mut fdt, "rtc", KVMTOOL_RTC_BASE)?;
    fdt.property_string("compatible", "motorola,mc146818")?;
    fdt.property_array_u64("reg", &[KVMTOOL_RTC_BASE, KVMTOOL_RTC_SIZE])?;
    fdt.end_node(rtc_node)?;

    let pcie_node = fdt_begin_node_addr(&mut fdt, "pci", KVMTOOL_PCI_CFG_BASE)?;
    fdt.property_string("device_type", "pci")?;
    fdt.property_u32("#address-cells", 3)?;
    fdt.property_u32("#size-cells", 2)?;
    fdt.property_null("dma-coherent")?;
    fdt.property_array_u32("bus-range", &[0, 0])?;
    fdt.property_string("compatible", "pci-host-ecam-generic")?;
    fdt.property_array_u64("reg", &[KVMTOOL_PCI_CFG_BASE, KVMTOOL_PCI_CFG_SIZE])?;
    fdt.property_array_u32(
        "ranges",
        &[
            FDT_PCI_RANGE_IOPORT,
            0,
            0,
            0,
            lo(KVMTOOL_IOPORT_BASE),
            0,
            lo(KVMTOOL_IOPORT_SIZE),
            FDT_PCI_RANGE_MMIO,
            0,
            lo(KVMTOOL_PCI_MMIO_BASE),
            0,
            lo(KVMTOOL_PCI_MMIO_BASE),
            0,
            lo(KVMTOOL_PCI_MMIO_SIZE),
        ],
    )?;
    // Now the interrupts. SPIs 64-127 are allocated for PCI, one per slot
    // number. Only pin #A is supported. Buses share the interrupts.
    spi = KVMTOOL_SPI_PCI;
    let mut irq_map: Vec<u32> = vec![];
    for i in 0..32 {
        let devfn = pci_devfn(i as u8, 0);
        irq_map.extend_from_slice(&[
            (devfn as u32) << 8,
            0,
            0,
            1, // pin
            gic_phandle,
            0,
            0,
            FDT_IRQ_SPI,
            spi,
            FDT_IRQ_LEVEL_HI,
        ]);
        spi += 1;
    }
    fdt.property_array_u32("interrupt-map", &irq_map)?;
    // Buses share the interrupt range, so only keep the slot number
    let devfn_mask = pci_devfn(0x1f, 0) as u32;
    fdt.property_array_u32("interrupt-map-mask", &[devfn_mask << 8, 0, 0, 0x7])?;
    fdt.property_u32("#interrupt-cells", 1)?;
    if kvmtool.has_its {
        // kvmtool provides msi-parent which isn't valid. msi-map should be used:
        fdt.property_array_u32("msi-map", &[0, its_phandle, 0, 0x10000])?;
    }
    fdt.end_node(pcie_node)?;

    if args.flash.is_some() {
        // Does it need to be supported for realms? edk2 ignores it
        todo!("add cfi-flash node");
    }

    fdt.end_node(root_node)?;
    let mut bytes = fdt.finish()?;
    if bytes.len() > FDT_SIZE {
        bail!(
            "generated DTB is too large ({} > {})",
            bytes.len(),
            FDT_SIZE
        );
    }
    bytes.resize(FDT_SIZE, 0);

    if let Some(filename) = output {
        write_dtb(filename, &bytes)?;
    }

    let blob = VmmBlob::from_bytes(bytes, kvmtool.dtb_base)?;
    realm.add_rim_blob(blob)?;

    Ok(())
}

/// Create the Realm parameters, vCPUs and blobs that contribute to RIM and REM.
///
pub fn build_params(args: &Args, lkvm_args: &KvmtoolArgs) -> Result<RealmConfig> {
    let mut realm = RealmConfig::from_args(args)?;
    let mut kvmtool = KvmtoolParams {
        mem_base: KVMTOOL_MEM_BASE,
        ..Default::default()
    };
    let mut pc = 0;

    parse_cmdline(lkvm_args, &mut realm, &mut kvmtool)?;

    realm.add_ram(kvmtool.mem_base, kvmtool.mem_size)?;

    if lkvm_args.kernel.is_some() {
        let Some(filename) = &args.kernel else {
            bail!("need kernel image");
        };

        pc = kvmtool.mem_base;
        let kernel = load_kernel(filename, kvmtool.mem_base)
            .with_context(|| filename.to_string())?;
        realm.add_rim_blob(kernel)?;
        kvmtool.use_kernel = true;
    }

    let mut dtb_base =
        kvmtool.mem_base + kvmtool.mem_size - (FDT_ALIGN + FDT_SIZE as u64);
    dtb_base = align_up(dtb_base, FDT_ALIGN);
    dtb_base = min(dtb_base, FDT_BASE);
    kvmtool.dtb_base = dtb_base;

    if lkvm_args.initrd.is_some() {
        let Some(filename) = &args.initrd else {
            bail!("need initrd image");
        };

        const INITRD_ALIGN: GuestAddress = 4;
        let mut initrd = VmmBlob::from_file(filename, dtb_base)?;
        initrd.guest_start -= initrd.size + INITRD_ALIGN;
        initrd.guest_start = align_up(initrd.guest_start, INITRD_ALIGN);
        kvmtool.initrd_base = initrd.guest_start;
        kvmtool.initrd_size = initrd.size;

        // note that this one isn't page aligned
        realm.add_rim_blob(initrd)?;
    }

    if lkvm_args.firmware.is_some() {
        let Some(filename) = &args.firmware else {
            bail!("need firmware image");
        };

        pc = kvmtool.firmware_base;
        let firmware = VmmBlob::from_file(filename, kvmtool.firmware_base)?;
        realm.add_rim_blob(firmware)?;
        kvmtool.use_firmware = true;
    }

    realm.add_rec(pc, [dtb_base, 0, 0, 0, 0, 0, 0, 0])?;

    // Now generate a DTB...
    add_dtb(lkvm_args, &mut realm, &kvmtool, &args.output_dtb)
        .context("while generating DTB")?;

    Ok(realm)
}
