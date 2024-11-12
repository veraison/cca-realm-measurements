#![allow(unused)]

use anyhow::Result;

pub const KIB: u64 = 1024;
pub const MIB: u64 = 1024 * KIB;
pub const GIB: u64 = 1024 * MIB;
pub const TIB: u64 = 1024 * GIB;
pub const PIB: u64 = 1024 * TIB;

/// Align @n down to @align
pub fn align_down(n: u64, align: u64) -> u64 {
    n & !(align - 1)
}

/// Align @n up to @align
pub fn align_up(n: u64, align: u64) -> u64 {
    (n + align - 1) & !(align - 1)
}

/// Return true if @n is aligned on @align
pub fn is_aligned(n: u64, align: u64) -> bool {
    (n & (align - 1)) == 0
}

/// Top 32 bits of a 64-bit address
pub fn hi(v: u64) -> u32 {
    (v >> 32) as u32
}

/// Bottom 32 bits of a 64-bit address
pub fn lo(v: u64) -> u32 {
    (v & 0xffff_ffff) as u32
}

/// Encode the PCI device-function number
pub fn pci_devfn(slot: u8, func: u8) -> u8 {
    assert!(slot < 0x20 && func < 0x8);
    (slot << 3) | func
}

/// Decode the PCI device number
pub fn pci_devfn_slot(devfn: u8) -> u8 {
    devfn >> 3
}

/// Convert SVE ZCR encoding to the vector length in bits.
pub fn sve_vq_to_vl(vq: u8) -> u16 {
    ((vq as u16) + 1) * 128
}

/// True if @vl is a valid SVE vector length in bits.
pub fn sve_vl_is_valid(vl: u16) -> bool {
    (vl % 128) == 0 && vl >= 128 && vl <= 2048
}

/// Convert SVE vector length in bit to the ZCR encoding.
pub fn sve_vl_to_vq(vl: u16) -> u8 {
    assert!(sve_vl_is_valid(vl));
    ((vl / 128) - 1) as u8
}

/// Parse a string with optional multiplier suffix `<n>[BKMGTP]`. Return the
/// size in bytes. Default multiplier is MiB.
pub fn parse_memory_size(s: &str) -> Result<u64> {
    let mut multiplier = MIB;
    let s = if let Some(ns) = s.strip_suffix('B') {
        multiplier = 1;
        ns
    } else if let Some(ns) = s.strip_suffix('K') {
        multiplier = KIB;
        ns
    } else if let Some(ns) = s.strip_suffix('M') {
        ns
    } else if let Some(ns) = s.strip_suffix('G') {
        multiplier = GIB;
        ns
    } else if let Some(ns) = s.strip_suffix('T') {
        multiplier = TIB;
        ns
    } else if let Some(ns) = s.strip_suffix('P') {
        multiplier = PIB;
        ns
    } else {
        s
    };

    let size: u64 = s.parse()?;
    Ok(size * multiplier)
}

pub fn buf_to_hex_str(b: &[u8]) -> String {
    b.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<String>>()
        .join("")
}
