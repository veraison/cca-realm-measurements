#![allow(unused)]
/// Utilities to generate device-trees
use vm_fdt::{FdtWriter, FdtWriterNode};

type Result<T> = core::result::Result<T, vm_fdt::Error>;

pub const FDT_IRQ_SPI: u32 = 0;
pub const FDT_IRQ_PPI: u32 = 1;
pub const FDT_IRQ_EDGE_LO_HI: u32 = 1;
pub const FDT_IRQ_EDGE_HI_LO: u32 = 2;
pub const FDT_IRQ_LEVEL_HI: u32 = 4;
pub const FDT_IRQ_LEVEL_LO: u32 = 8;

pub const FDT_PCI_RANGE_RELOCATABLE: u32 = 0x80000000;
pub const FDT_PCI_RANGE_PREFETCHABLE: u32 = 0x40000000;
pub const FDT_PCI_RANGE_ALIASED: u32 = 0x20000000;
pub const FDT_PCI_RANGE_MMIO_64BIT: u32 = 0x03000000;
pub const FDT_PCI_RANGE_MMIO: u32 = 0x02000000;
pub const FDT_PCI_RANGE_IOPORT: u32 = 0x01000000;
pub const FDT_PCI_RANGE_CONFIG: u32 = 0x00000000;

/// Begin a node whose name is composed of node_name and unit_address
pub fn fdt_begin_node_addr(
    fdt: &mut FdtWriter,
    node_name: &str,
    unit_address: u64,
) -> Result<FdtWriterNode> {
    let name = format!("{}@{:x}", node_name, unit_address);
    fdt.begin_node(&name)
}

pub fn fdt_add_mem(fdt: &mut FdtWriter, base: u64, size: u64) -> Result<()> {
    let mem_node = fdt_begin_node_addr(fdt, "memory", base)?;
    fdt.property_string("device_type", "memory")?;
    fdt.property_array_u64("reg", &[base, size])?;
    fdt.end_node(mem_node)
}

pub fn fdt_add_cpu(fdt: &mut FdtWriter, num_cpus: usize) -> Result<()> {
    let cpus_node = fdt.begin_node("cpus")?;
    fdt.property_u32("#size-cells", 0)?;
    fdt.property_u32("#address-cells", 1)?;
    for i in 0..num_cpus {
        let node_name = format!("cpu@{i}");
        let cpu_node = fdt.begin_node(&node_name)?;
        fdt.property_u32("reg", i as u32)?;
        fdt.property_string("enable-method", "psci")?;
        fdt.property_string("compatible", "arm,armv8")?;
        fdt.property_string("device_type", "cpu")?;
        fdt.end_node(cpu_node)?;
    }
    fdt.end_node(cpus_node)
}

pub fn fdt_add_gic(
    fdt: &mut FdtWriter,
    gic_reg: &[u64],
    its_reg: Option<[u64; 2]>,
    gic_phandle: u32,
    its_phandle: u32,
) -> Result<()> {
    let gic_node = fdt_begin_node_addr(fdt, "intc", gic_reg[0])?;
    fdt.property_phandle(gic_phandle)?;
    fdt.property_array_u64("reg", gic_reg)?;
    let num_redist = (gic_reg.len() - 2) / 2;
    fdt.property_u32("#redistributor-regions", num_redist as u32)?;
    fdt.property_string("compatible", "arm,gic-v3")?;
    fdt.property_null("ranges")?;
    fdt.property_u32("#size-cells", 2)?;
    fdt.property_u32("#address-cells", 2)?;
    fdt.property_null("interrupt-controller")?;
    fdt.property_u32("#interrupt-cells", 3)?;

    if let Some(reg) = its_reg {
        let its_node = fdt_begin_node_addr(fdt, "its", reg[0])?;
        fdt.property_phandle(its_phandle)?;
        fdt.property_array_u64("reg", &reg)?;
        fdt.property_u32("#msi-cells", 1)?;
        fdt.property_null("msi-controller")?;
        fdt.property_string("compatible", "arm,gic-v3-its")?;
        fdt.end_node(its_node)?;
    }
    fdt.end_node(gic_node)
}

pub fn fdt_add_timer(fdt: &mut FdtWriter, irqs: &[u32], trigger: u32) -> Result<()> {
    let timer_node = fdt.begin_node("timer")?;
    let mut interrupts = vec![];

    for irq in irqs {
        interrupts.push(FDT_IRQ_PPI);
        interrupts.push(*irq);
        interrupts.push(trigger);
    }
    fdt.property_array_u32("interrupts", &interrupts)?;
    fdt.property_null("always-on")?;
    fdt.property_string_list(
        "compatible",
        vec!["arm,armv8-timer".to_string(), "arm,armv7-timer".to_string()],
    )?;
    fdt.end_node(timer_node)
}

pub fn fdt_add_pmu(fdt: &mut FdtWriter, irq: u32) -> Result<()> {
    let pmu_node = fdt.begin_node("pmu")?;
    fdt.property_array_u32("interrupts", &[FDT_IRQ_PPI, irq, FDT_IRQ_LEVEL_HI])?;
    fdt.property_string("compatible", "arm,armv8-pmuv3")?;
    fdt.end_node(pmu_node)
}

/// RMM supports a subset of PSCI functions consistent with PSCI v1.0
pub fn fdt_add_psci(fdt: &mut FdtWriter) -> Result<()> {
    let psci_node = fdt.begin_node("psci")?;
    // The binding requires cpu_on and cpu_off properties when compatible arm,psci
    fdt.property_u32("cpu_on", 0xc4000003)?;
    fdt.property_u32("cpu_off", 0x84000002)?;
    fdt.property_string("method", "smc")?;
    fdt.property_string_list(
        "compatible",
        vec![
            "arm,psci-1.0".to_string(),
            "arm,psci-0.2".to_string(),
            "arm,psci".to_string(),
        ],
    )?;
    fdt.end_node(psci_node)
}

/// Start a VM FDT, with a few standard properties.
/// Both address and size cells for the root bus are 2.
///
/// @mem: memory start address and size
/// @cpu_count: number of vCPUs
/// @intc_phandle: phandle of the interrupt controller node (an arbitrary 32-bit
///     value, unique within the DT
/// @bootargs: kernel command-line
/// @initrd: initrd start addess and size
pub fn fdt_new(
    mem: (u64, u64),
    cpu_count: usize,
    intc_phandle: u32,
    bootargs: Option<&str>,
    initrd: Option<(u64, u64)>,
) -> Result<(FdtWriter, FdtWriterNode)> {
    let mut fdt = FdtWriter::new()?;

    let root_node = fdt.begin_node("")?;
    fdt.property_string("compatible", "linux,dummy-virt")?;
    fdt.property_string("model", "linux,dummy-virt-realm")?;
    fdt.property_u32("#address-cells", 2)?;
    fdt.property_u32("#size-cells", 2)?;
    fdt.property_u32("interrupt-parent", intc_phandle)?;

    let chosen_node = fdt.begin_node("chosen")?;

    if let Some(v) = bootargs {
        fdt.property_string("bootargs", v)?;
    }

    if let Some((start, size)) = initrd {
        fdt.property_u64("linux,initrd-start", start)?;
        fdt.property_u64("linux,initrd-end", start + size)?;
    }
    fdt.end_node(chosen_node)?;

    fdt_add_mem(&mut fdt, mem.0, mem.1)?;
    fdt_add_cpu(&mut fdt, cpu_count)?;
    fdt_add_psci(&mut fdt)?;

    Ok((fdt, root_node))
}
