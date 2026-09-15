/// Initialize Realm parameters for the cloud-hypervisor VM
//
use crate::command_line::*;
use crate::fdt::*;
use crate::realm::*;
use crate::realm_config::*;
use crate::utils::*;
use crate::vmm::*;

use anyhow::{bail, Context, Result};

const CLOUDHV_GIC_DIST_BASE: u64 = 0x08ff0000;
const CLOUDHV_GIC_DIST_SIZE: u64 = 0x10000;
const CLOUDHV_GIC_REDIST_SIZE: u64 = 0x20000;
const CLOUDHV_GIC_ITS_SIZE: u64 = 0x20000;
const CLOUDHV_UART_BASE: u64 = 0x09000000;
const CLOUDHV_UART_SIZE: u64 = 0x1000;
const CLOUDHV_RTC_BASE: u64 = 0x09010000;
const CLOUDHV_RTC_SIZE: u64 = 0x1000;

const CLOUDHV_MEM_START: u64 = 0x40000000;

const CLOUDHV_PCI_CFG_BASE: u64 = 0x30000000;
const CLOUDHV_PCI_CFG_SIZE: u64 = 0x100000;
const CLOUDHV_PCI_IOPORT_BASE: u64 = 0x09050000;
const CLOUDHV_PCI_IOPORT_SIZE: u64 = 0x10000;
const CLOUDHV_PCI_MMIO_BASE: u64 = 0x10000000;
const CLOUDHV_PCI_MMIO_SIZE: u64 = 0x20000000;

const CLOUDHV_DT_BASE: u64 = CLOUDHV_MEM_START;
const CLOUDHV_KERNEL_BASE: u64 = CLOUDHV_MEM_START + 0x400000;

// FIXME: fix IRQ map
const CLOUDHV_SPI_RTC: u32 = 0x8;
const CLOUDHV_SPI_UART: u32 = 0xb;

/// Cloud hypervisor arguments.
// Define anything that could be passed to cloud-hypervisor, even those we won't
// inspect ourself, so the arg parser doesn't complain.
#[derive(Debug, Clone, clap::Args)]
pub struct CloudHVArgs {
    #[arg(long)]
    cpus: Option<String>,

    #[arg(long)]
    platform: Option<String>,

    #[arg(long)]
    memory: Option<String>,

    #[arg(long)]
    memory_zone: Vec<String>,

    #[arg(long)]
    firmware: Option<String>,

    #[arg(long)]
    kernel: Option<String>,

    #[arg(long)]
    initramfs: Option<String>,

    #[arg(long)]
    cmdline: Option<String>,

    #[arg(long)]
    rate_limit_group: Vec<String>,

    #[arg(long)]
    disk: Vec<String>,

    #[arg(long)]
    net: Vec<String>,

    #[arg(long)]
    rng: Option<String>,

    #[arg(long)]
    balloon: Option<String>,

    #[arg(long)]
    fs: Vec<String>,

    #[arg(long)]
    pmem: Vec<String>,

    #[arg(long)]
    serial: Option<String>,

    #[arg(long)]
    console: Option<String>,

    #[arg(long)]
    device: Vec<String>,

    #[arg(long)]
    user_device: Vec<String>,

    #[arg(long)]
    vdpa: Vec<String>,

    #[arg(long)]
    vsock: Option<String>,

    #[arg(long)]
    pvpanic: bool,

    #[arg(long)]
    numa: Vec<String>,

    #[arg(long)]
    pci_segment: Vec<String>,

    #[arg(long)]
    watchdog: bool,

    #[arg(long)]
    log_file: Option<String>,

    #[arg(long)]
    api_socket: Option<String>,

    #[arg(long)]
    event_monitor: Option<String>,

    #[arg(long)]
    restore: Option<String>,

    #[arg(long)]
    seccomp: Option<String>,

    #[arg(long)]
    tpm: Option<String>,

    #[arg(short, action = clap::ArgAction::Count)]
    verbose: u8,

    #[arg(long)]
    dtb: Option<String>,
}

struct CloudHVParams {
    num_cpus: usize,
    mem_size: u64,
    initrd: Option<(u64, u64)>,
    bootargs: Option<String>,
    serial: bool, // instantiate pl011
}

fn parse_platform(arg: &Option<String>, realm: &mut RealmConfig) -> Result<()> {
    let Some(arg) = arg else {
        return Ok(());
    };

    for item in arg.split(',') {
        let Some((name, val)) = item.split_once('=') else {
            bail!("malformed --platform param {}", item);
        };

        match name {
            "personalization_value" => {
                let rpv = PersonalizationValue::from_base64(val)?;
                realm.set_personalization_value(rpv);
            }
            "measurement_algo" => realm.set_measurement_algo(val)?,
            _ => (),
        }
    }
    Ok(())
}

fn parse_cpus(arg: &Option<String>, cloudhv: &mut CloudHVParams) -> Result<()> {
    let Some(arg) = arg else {
        return Ok(());
    };

    for item in arg.split(',') {
        let Some((name, val)) = item.split_once('=') else {
            bail!("malformed --cpu param {}", item);
        };

        match name {
            "boot" => cloudhv.set_num_cpus(val.parse().context("--cpus")?),
            _ => log::warn!("ignored --cpus parameter {}", name),
        }
    }
    Ok(())
}

fn parse_memory(arg: &Option<String>, cloudhv: &mut CloudHVParams) -> Result<()> {
    let Some(arg) = arg else {
        return Ok(());
    };

    for item in arg.split(',') {
        let Some((name, val)) = item.split_once('=') else {
            bail!("malformed --memory param {}", item);
        };

        match name {
            "size" => {
                cloudhv.set_mem_size(parse_memory_size(val).context("--memory")?)?
            }
            _ => log::warn!("ignored --memory parameter {}", name),
        }
    }
    Ok(())
}

/// Parse arguments to cloud-hypervisor
fn parse_cmdline(
    args: &CloudHVArgs,
    cloudhv: &mut CloudHVParams,
    realm: &mut RealmConfig,
) -> Result<()> {
    parse_platform(&args.platform, realm)?;
    parse_cpus(&args.cpus, cloudhv)?;
    parse_memory(&args.memory, cloudhv)?;

    if let Some(serial) = &args.serial {
        if serial == "off" {
            cloudhv.serial = false;
        }
    }
    Ok(())
}

impl VmmParams for CloudHVParams {
    fn set_initrd(&mut self, base: GuestAddress, size: u64) {
        self.initrd = Some((base, size));
    }

    fn initrd(&self) -> Option<(u64, u64)> {
        self.initrd
    }

    fn set_mem_size(&mut self, mem_size: u64) -> VmmResult<()> {
        self.mem_size = mem_size;
        Ok(())
    }

    fn mem(&self) -> (u64, u64) {
        (CLOUDHV_MEM_START, self.mem_size)
    }

    fn set_num_cpus(&mut self, num_cpus: usize) {
        self.num_cpus = num_cpus;
    }

    fn num_cpus(&self) -> usize {
        self.num_cpus
    }

    fn pmu(&self) -> bool {
        true
    }

    fn set_its(&mut self, _its: bool) {}

    fn set_bootargs(&mut self, bootargs: Option<&str>) {
        self.bootargs = bootargs.map(|s| s.to_string());
    }

    fn bootargs(&self) -> Option<&str> {
        self.bootargs.as_deref()
    }
}

impl DTBGenerator for CloudHVParams {
    fn gen_dtb(&self) -> VmmResult<Vec<u8>> {
        let gic_phandle: u32 = 1;
        let its_phandle: u32 = 2;
        let clock_phandle: u32 = 3;

        let (mut fdt, root_node) = self.create_fdt(gic_phandle)?;

        let gic_redist_size = (self.num_cpus() as u64) * CLOUDHV_GIC_REDIST_SIZE;
        let gic_redist_base = CLOUDHV_GIC_DIST_BASE - gic_redist_size;
        let gic_its_base = gic_redist_base - CLOUDHV_GIC_ITS_SIZE;

        self.add_gic_node(
            &mut fdt,
            &[
                CLOUDHV_GIC_DIST_BASE,
                CLOUDHV_GIC_DIST_SIZE,
                gic_redist_base,
                gic_redist_size,
            ],
            Some([gic_its_base, CLOUDHV_GIC_ITS_SIZE]),
            gic_phandle,
            its_phandle,
        )?;

        self.add_timer_node(&mut fdt, &[13, 14, 11], FDT_IRQ_LEVEL_HI)?;
        self.add_pmu_node(&mut fdt, 7)?;

        let clk_node = fdt.begin_node("apb-pclk")?;
        fdt.property_phandle(clock_phandle)?;
        fdt.property_string("clock-output-names", "clk24mhz")?;
        fdt.property_u32("clock-frequency", 24000000)?;
        fdt.property_u32("#clock-cells", 0)?;
        fdt.property_string("compatible", "fixed-clock")?;
        fdt.end_node(clk_node)?;

        let rtc_node = fdt_begin_node_addr(&mut fdt, "pl031", CLOUDHV_RTC_BASE)?;
        fdt.property_string("clock-names", "apb_pclk")?;
        fdt.property_array_u64("reg", &[CLOUDHV_RTC_BASE, CLOUDHV_RTC_SIZE])?;
        fdt.property_u32("clocks", clock_phandle)?;
        let interrupts = [FDT_IRQ_SPI, CLOUDHV_SPI_RTC, FDT_IRQ_LEVEL_HI];
        fdt.property_array_u32("interrupts", &interrupts)?;
        fdt.property_string_list(
            "compatible",
            vec!["arm,pl031".to_string(), "arm,primecell".to_string()],
        )?;
        fdt.end_node(rtc_node)?;

        if self.serial {
            let uart_node = fdt_begin_node_addr(&mut fdt, "pl011", CLOUDHV_UART_BASE)?;
            fdt.property_string("clock-names", "apb_pclk")?;
            fdt.property_array_u64("reg", &[CLOUDHV_UART_BASE, CLOUDHV_UART_SIZE])?;
            fdt.property_u32("clocks", clock_phandle)?;
            fdt.property_array_u32(
                "interrupts",
                &[FDT_IRQ_SPI, CLOUDHV_SPI_UART, FDT_IRQ_EDGE_LO_HI],
            )?;
            fdt.property_string_list(
                "compatible",
                vec!["arm,pl011".to_string(), "arm,primecell".to_string()],
            )?;
            fdt.end_node(uart_node)?;
        }

        let pcie_node = fdt_begin_node_addr(&mut fdt, "pcie", CLOUDHV_PCI_CFG_BASE)?;
        // FIXME: Generate interrupt-map. Does CH support intx?
        //
        // TODO: more than 8GB RAM moves the PCI high region?
        let pci_high_base = 0x2_00000000;
        // FIXME: probably not that.
        let pci_high_size = 0x3fff_00000000 - pci_high_base;
        fdt.property_array_u32(
            "ranges",
            &[
                FDT_PCI_RANGE_IOPORT,
                0,
                0,
                0,
                lo(CLOUDHV_PCI_IOPORT_BASE),
                0,
                lo(CLOUDHV_PCI_IOPORT_SIZE),
                FDT_PCI_RANGE_MMIO,
                0,
                lo(CLOUDHV_PCI_MMIO_BASE),
                0,
                lo(CLOUDHV_PCI_MMIO_BASE),
                0,
                lo(CLOUDHV_PCI_MMIO_SIZE),
                FDT_PCI_RANGE_MMIO_64BIT,
                hi(pci_high_base),
                lo(pci_high_base),
                hi(pci_high_base),
                lo(pci_high_base),
                hi(pci_high_size),
                lo(pci_high_size),
            ],
        )?;
        fdt.property_array_u64("reg", &[CLOUDHV_PCI_CFG_BASE, CLOUDHV_PCI_CFG_SIZE])?;
        fdt.property_array_u32("msi-map", &[0, its_phandle, 0, 0x100])?;
        fdt.property_null("dma-coherent")?;
        fdt.property_array_u32("bus-range", &[0, 0])?;
        fdt.property_u32("linux,pci-domain", 0)?;
        fdt.property_u32("#size-cells", 2)?;
        fdt.property_u32("#address-cells", 3)?;
        fdt.property_string("device_type", "pci")?;
        fdt.property_string("compatible", "pci-host-ecam-generic")?;
        fdt.end_node(pcie_node)?;

        fdt.end_node(root_node)?;
        Ok(fdt.finish()?)
    }
}

/// Create a [RealmConfig] from the cloud-hypervisor command-line arguments.
pub fn build_params(args: &Args, cloudhv_args: &CloudHVArgs) -> Result<RealmConfig> {
    let mut realm = RealmConfig::from_args(args)?;
    let mut cloudhv = CloudHVParams {
        num_cpus: 1,
        mem_size: 512 * MIB,
        initrd: None,
        bootargs: None,
        serial: true,
    };

    realm.params.restrict_ipa_bits(48)?;
    realm.set_measurement_algo("sha512")?;

    parse_cmdline(cloudhv_args, &mut cloudhv, &mut realm)?;

    realm.add_ram(CLOUDHV_MEM_START, cloudhv.mem_size)?;

    if cloudhv_args.kernel.is_some() {
        let Some(filename) = &args.kernel else {
            bail!("need kernel image");
        };
        let kernel = load_kernel(filename, CLOUDHV_KERNEL_BASE)?;

        realm.add_rim_blob(kernel)?;
    }

    if cloudhv_args.initramfs.is_some() {
        let Some(filename) = &args.initrd else {
            bail!("need initrd image");
        };

        let mut initrd = VmmBlob::from_file(filename, 0);
        // Align on the host page size
        let initrd_size = align_up(initrd.len()?, cca_rmm::RMM_GRANULE);
        let initrd_start = CLOUDHV_MEM_START + cloudhv.mem_size - initrd_size;
        initrd.guest_start = initrd_start;
        cloudhv.set_initrd(initrd_start, initrd.len()?);
        realm.add_rim_blob(initrd)?;
    }

    realm.add_rec(CLOUDHV_KERNEL_BASE, [CLOUDHV_DT_BASE, 0, 0, 0, 0, 0, 0, 0])?;

    cloudhv.set_bootargs(cloudhv_args.cmdline.as_deref());

    add_dtb(
        &mut realm,
        &args.dtb,
        &args.output_dtb,
        CLOUDHV_DT_BASE,
        &cloudhv,
    )
    .context("while generating DTB")?;
    Ok(realm)
}
