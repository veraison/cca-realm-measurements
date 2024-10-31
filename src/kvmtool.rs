use std::cmp::{max, min};

use anyhow::{bail, Context, Result};

use crate::command_line::*;
use crate::dtb_surgeon::*;
use crate::fdt::*;
use crate::realm_config::*;
use crate::utils::*;
use crate::vmm::*;

use vm_fdt::FdtWriter;

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

const KVMTOOL_LOG_SIZE: u64 = 64 * KIB;

const KVMTOOL_SPI_UART: u32 = 0;
const KVMTOOL_SPI_VIRTIO_MMIO: u32 = 4;
const KVMTOOL_SPI_PCI: u32 = 64;

const KVMTOOL_GIC_PHANDLE: u32 = 1;
const KVMTOOL_ITS_PHANDLE: u32 = 2;

const FDT_DEFAULT_LIMIT: GuestAddress = KVMTOOL_MEM_BASE + 256 * MIB;
const FDT_ALIGN: GuestAddress = 2 * MIB;
const FDT_SIZE: usize = 0x10000;

/// lkvm run arguments.
// Define anything that could be passed to kvmtool, even
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
    measurement_log: bool,

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

#[derive(Copy, Clone, Debug, Default, PartialEq)]
enum VirtioTransport {
    #[default]
    Pci,
    Mmio,
}

#[derive(Copy, Clone, Debug, Default, PartialEq)]
enum DeviceType {
    #[default]
    Virtio,
}

/// Kvmtool configuration
#[derive(Clone, Debug, Default)]
pub struct KvmtoolParams {
    /// Number of vCPUs
    pub num_cpus: usize,
    /// Base address of RAM
    pub mem_base: GuestAddress,
    /// Size of RAM
    pub mem_size: GuestAddress,
    /// Is the GIC ITS enabled
    pub has_its: bool,
    /// Kernel command-line arguments
    pub bootargs: Option<String>,

    initrd_base: GuestAddress,
    initrd_size: GuestAddress,
    firmware_base: GuestAddress,
    virtio_transport: VirtioTransport,
    virtio_mmio_devices: usize,
    use_kernel: bool,
    use_firmware: bool,
    pmu: bool,

    dtb_template: Option<Vec<u8>>,

    /* base, size */
    log: Option<(GuestAddress, u64)>,
}

impl KvmtoolParams {
    /// Create a new KvmtoolParams
    pub fn new() -> Self {
        KvmtoolParams {
            mem_base: KVMTOOL_MEM_BASE,
            ..Default::default()
        }
    }
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

    kvmtool.set_mem_size(parse_memory_size(mem_str).context("-m")?);
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
    kvmtool.set_its(true);
    if let Some(v) = &args.irqchip {
        match v.as_str() {
            "gicv3" => kvmtool.set_its(false),
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
        kvmtool.set_num_cpus(cpus);
    } else {
        bail!("number of vCPUs is not known");
    }
    parse_mem(&args.mem, kvmtool)?;

    if let Some(p) = &args.params {
        kvmtool.set_bootargs(p);
    }

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
        realm.set_personalization_value(v.as_bytes().try_into()?);
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

impl DTBSurgeon for KvmtoolParams {
    fn handle_node(&self, fdt: &mut FdtWriter, node_name: &str) -> DTBResult<bool> {
        match node_name {
            "cpus" => {
                let cpus_node = fdt.begin_node("cpus")?;
                fdt.property_u32("#address-cells", 1)?;
                fdt.property_u32("#size-cells", 0)?;
                for i in 0..self.num_cpus {
                    let node_name = format!("cpu@{i}");
                    let cpu_node = fdt.begin_node(&node_name)?;
                    fdt.property_string("device_type", "cpu")?;
                    fdt.property_string("compatible", "arm,arm-v8")?;
                    fdt.property_string("enable-method", "psci")?;
                    fdt.property_u32("reg", i as u32)?;
                    fdt.end_node(cpu_node)?;
                }
                fdt.end_node(cpus_node)?;
                Ok(true)
            }
            "intc" => {
                // The redistributor size depends on the number of vCPUs. Also
                // the ITS may be disabled.
                let redist_size = (self.num_cpus as u64) * KVMTOOL_GIC_REDIST_SIZE;
                let redist_base = KVMTOOL_GIC_DIST_BASE - redist_size;

                let gic_reg = &[
                    KVMTOOL_GIC_DIST_BASE,
                    KVMTOOL_GIC_DIST_SIZE,
                    redist_base,
                    redist_size,
                ];

                let gic_node = fdt.begin_node("intc")?;
                fdt.property_string("compatible", "arm,gic-v3")?;
                fdt.property_u32("#interrupt-cells", 3)?;
                fdt.property_null("interrupt-controller")?;
                fdt.property_array_u64("reg", gic_reg)?;
                fdt.property_phandle(KVMTOOL_GIC_PHANDLE)?;
                fdt.property_u32("#address-cells", 2)?;
                fdt.property_u32("#size-cells", 2)?;
                fdt.property_null("ranges")?;

                if self.has_its {
                    let its_size = KVMTOOL_GIC_ITS_SIZE;
                    let its_base = redist_base - its_size;

                    let its_node = fdt.begin_node("msic")?;
                    fdt.property_string("compatible", "arm,gic-v3-its")?;
                    fdt.property_null("msi-controller")?;
                    fdt.property_phandle(KVMTOOL_ITS_PHANDLE)?;
                    fdt.property_array_u64("reg", &[its_base, its_size])?;
                    fdt.end_node(its_node)?;
                }
                fdt.end_node(gic_node)?;
                Ok(true)
            }
            "reserved-memory" => {
                let Some((log_base, log_size)) = self.log else {
                    return Ok(true);
                };
                // Add a node for the measurement log within reserved-memory
                let resv_mem_node = fdt.begin_node("reserved-memory")?;
                fdt.property_u32("#address-cells", 2)?;
                fdt.property_u32("#size-cells", 2)?;
                fdt.property_null("ranges")?;
                let log_node = fdt_begin_node_addr(fdt, "event-log", log_base)?;
                fdt.property_string("compatible", "cc-event-log")?;
                fdt.property_array_u64("reg", &[log_base, log_size])?;

                fdt.end_node(log_node)?;
                fdt.end_node(resv_mem_node)?;
                Ok(true)
            }
            "pmu" => {
                // Drop the node if PMU is disabled. We assume the template is
                // generated with PMU enabled. Luckily the property strings are
                // used by other nodes so the strings table doesn't change.
                Ok(!self.pmu)
            }
            // TODO: virtio-mmio: dynamic SPIs and number of devices. Need to be
            // inserted somewhere within the DTB. Before the RTC I think?
            _ => Ok(false),
        }
    }

    fn mem(&self) -> (u64, u64) {
        (self.mem_base, self.mem_size)
    }

    fn initrd(&self) -> Option<(u64, u64)> {
        Some((self.initrd_base, self.initrd_size))
    }

    fn bootargs(&self) -> Option<&str> {
        self.bootargs.as_deref()
    }
}

fn resize_dtb(mut dtb: Vec<u8>) -> VmmResult<Vec<u8>> {
    if dtb.len() > FDT_SIZE {
        return Err(VmmError::Other(format!(
            "generated DTB is too large ({} > {FDT_SIZE})",
            dtb.len()
        )));
    }
    dtb.resize(FDT_SIZE, 0);
    Ok(dtb)
}

impl DTBGenerator for KvmtoolParams {
    fn set_initrd(&mut self, base: GuestAddress, size: u64) {
        self.initrd_base = base;
        self.initrd_size = size;
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
        self.pmu = pmu;
    }

    fn set_its(&mut self, its: bool) {
        self.has_its = its;
    }

    fn set_bootargs(&mut self, bootargs: &str) {
        // FIXME: kvmtool generates a command-line depending on
        // arguments. We need to try to reproduce it more
        // accurately. But really, we should remove this from
        // kvmtool because it's a friggin pain to reproduce in black
        // box mode.)
        self.bootargs = Some(" console=hvc0 root=/dev/vda rw ".to_string() + bootargs);
    }

    fn set_template(&mut self, template: Vec<u8>) -> VmmResult<()> {
        self.dtb_template = Some(template);
        Ok(())
    }

    fn gen_dtb(&self) -> VmmResult<Vec<u8>> {
        if let Some(input) = &self.dtb_template {
            return resize_dtb(self.update_dtb(input)?);
        }

        let initrd = if self.initrd_size != 0 {
            Some((self.initrd_base, self.initrd_size))
        } else {
            None
        };

        let (mut fdt, root_node) = fdt_new(
            self.mem(),
            self.num_cpus,
            KVMTOOL_GIC_PHANDLE,
            self.bootargs.as_deref(),
            initrd,
        )?;

        self.handle_node(&mut fdt, "intc")?;
        self.handle_node(&mut fdt, "reserved-memory")?;

        fdt_add_timer(&mut fdt, &[13, 14, 11], FDT_IRQ_LEVEL_LO)?;
        if self.pmu {
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
        for i in 0..self.virtio_mmio_devices {
            let size = KVMTOOL_VIRTIO_MMIO_SIZE;
            let addr = KVMTOOL_VIRTIO_MMIO_BASE + i as u64 * size;
            let mmio_node = fdt_begin_node_addr(&mut fdt, "virtio", addr)?;
            fdt.property_string("compatible", "virtio,mmio")?;
            fdt.property_array_u64("reg", &[addr, size])?;
            fdt.property_null("dma-coherent")?;
            fdt.property_array_u32(
                "interrupts",
                &[FDT_IRQ_SPI, spi, FDT_IRQ_EDGE_LO_HI],
            )?;
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
                KVMTOOL_GIC_PHANDLE,
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
        if self.has_its {
            // kvmtool provides msi-parent which isn't valid. msi-map should be used:
            fdt.property_array_u32("msi-map", &[0, KVMTOOL_ITS_PHANDLE, 0, 0x10000])?;
        }
        fdt.end_node(pcie_node)?;

        fdt.end_node(root_node)?;
        resize_dtb(fdt.finish()?)
    }
}

/// Create a [RealmConfig] from the kvmtool command-line.
pub fn build_params(args: &Args, lkvm_args: &KvmtoolArgs) -> Result<RealmConfig> {
    let mut realm = RealmConfig::from_args(args)?;
    let mut kvmtool = KvmtoolParams::new();
    let mut pc = 0;

    parse_cmdline(lkvm_args, &mut realm, &mut kvmtool)?;

    let mut dtb_base = kvmtool.mem_base + kvmtool.mem_size;
    dtb_base = min(dtb_base, FDT_DEFAULT_LIMIT);

    if lkvm_args.measurement_log {
        kvmtool.set_log_location(dtb_base - KVMTOOL_LOG_SIZE, KVMTOOL_LOG_SIZE);
        dtb_base -= KVMTOOL_LOG_SIZE;
    }

    dtb_base -= FDT_ALIGN + FDT_SIZE as u64;
    dtb_base = align_up(dtb_base, FDT_ALIGN);

    realm.add_ram(kvmtool.mem_base, kvmtool.mem_size)?;

    kvmtool.set_pmu(realm.params.pmu.unwrap_or(false));

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

    if lkvm_args.initrd.is_some() {
        let Some(filename) = &args.initrd else {
            bail!("need initrd image");
        };

        const INITRD_ALIGN: GuestAddress = 4;
        let mut initrd = VmmBlob::from_file(filename, dtb_base);
        initrd.guest_start -= initrd.len()? + INITRD_ALIGN;
        initrd.guest_start = align_up(initrd.guest_start, INITRD_ALIGN);
        kvmtool.set_initrd(initrd.guest_start, initrd.len()?);

        // note that this one isn't page aligned
        realm.add_rim_blob(initrd)?;
    }

    if lkvm_args.firmware.is_some() {
        let Some(filename) = &args.firmware else {
            bail!("need firmware image");
        };

        pc = kvmtool.firmware_base;
        let firmware = VmmBlob::from_file(filename, kvmtool.firmware_base);
        realm.add_rim_blob(firmware)?;
        kvmtool.use_firmware = true;
    }

    if lkvm_args.flash.is_some() {
        // Does it need to be supported for realms? edk2 ignores it.
        // This would add a DTB node
        todo!("cfi-flash not supported");
    }

    realm.add_rec(pc, [dtb_base, 0, 0, 0, 0, 0, 0, 0])?;

    if let Some((log_base, log_size)) = kvmtool.log {
        realm.add_rim_unmeasured(log_base, log_size)?;
    }

    // Now generate a DTB...
    if let Some(input_dtb) = &args.input_dtb {
        kvmtool.set_template(std::fs::read(input_dtb)?)?;
    }
    kvmtool
        .add_dtb(&args.output_dtb, dtb_base, &mut realm)
        .context("while generating DTB")?;

    Ok(realm)
}
