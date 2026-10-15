#![allow(unused)]
/// Utilities to generate device-trees
use crate::vmm::{VmmParams, VmmResult};
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

/// Generate a device tree blob
pub trait DTBGenerator: VmmParams {
    /// Generate a DTB
    fn gen_dtb(&self) -> VmmResult<Vec<u8>>;

    /// Describe memory from VmmParams::mem()
    fn add_mem_node(&self, fdt: &mut FdtWriter) -> Result<()> {
        let (base, size) = self.mem();
        let mem_node = fdt_begin_node_addr(fdt, "memory", base)?;
        fdt.property_string("device_type", "memory")?;
        fdt.property_array_u64("reg", &[base, size])?;
        fdt.end_node(mem_node)
    }

    /// Describe VmmParams::num_cpus() vCPUs
    fn add_cpu_node(&self, fdt: &mut FdtWriter) -> Result<()> {
        let cpus_node = fdt.begin_node("cpus")?;
        fdt.property_u32("#size-cells", 0)?;
        fdt.property_u32("#address-cells", 1)?;
        for i in 0..self.num_cpus() {
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

    /// Describe GICv3
    fn add_gic_node(
        &self,
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

    /// Describe generic armv8 timer
    fn add_timer_node(
        &self,
        fdt: &mut FdtWriter,
        irqs: &[u32],
        trigger: u32,
    ) -> Result<()> {
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

    /// Describe PMU node
    fn add_pmu_node(&self, fdt: &mut FdtWriter, irq: u32) -> Result<()> {
        if !self.pmu() {
            return Ok(());
        }
        let pmu_node = fdt.begin_node("pmu")?;
        fdt.property_array_u32("interrupts", &[FDT_IRQ_PPI, irq, FDT_IRQ_LEVEL_HI])?;
        fdt.property_string("compatible", "arm,armv8-pmuv3")?;
        fdt.end_node(pmu_node)
    }

    /// RMM supports a subset of PSCI functions consistent with PSCI v1.0
    fn add_psci_node(&self, fdt: &mut FdtWriter) -> Result<()> {
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

    /// Describe event-log inside a reserved-memory node
    fn add_reserved_memory_node(&self, fdt: &mut FdtWriter) -> Result<()> {
        let Some((log_base, log_size)) = self.log_location() else {
            return Ok(());
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
        Ok(())
    }

    /// Start a VM FDT, with a few standard properties.
    /// Both address and size cells for the root bus are 2.
    ///
    /// @intc_phandle: phandle of the interrupt controller node (an arbitrary 32-bit
    ///     value, unique within the DT
    fn create_fdt(&self, intc_phandle: u32) -> Result<(FdtWriter, FdtWriterNode)> {
        let mut fdt = FdtWriter::new()?;

        let root_node = fdt.begin_node("")?;
        fdt.property_string("compatible", "linux,dummy-virt")?;
        fdt.property_string("model", "linux,dummy-virt-realm")?;
        fdt.property_u32("#address-cells", 2)?;
        fdt.property_u32("#size-cells", 2)?;
        fdt.property_u32("interrupt-parent", intc_phandle)?;

        let chosen_node = fdt.begin_node("chosen")?;

        if let Some(v) = self.bootargs() {
            fdt.property_string("bootargs", v)?;
        }

        if let Some((start, size)) = self.initrd() {
            fdt.property_u64("linux,initrd-start", start)?;
            fdt.property_u64("linux,initrd-end", start + size)?;
        }
        fdt.end_node(chosen_node)?;

        self.add_mem_node(&mut fdt)?;
        self.add_cpu_node(&mut fdt)?;
        self.add_psci_node(&mut fdt)?;

        Ok((fdt, root_node))
    }
}
