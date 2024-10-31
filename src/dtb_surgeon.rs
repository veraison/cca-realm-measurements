/// Perform small modifications to a device-tree blob, such as number of CPUs or
/// initrd size, while trying to remain identical to the equivalent DTB
/// generated by a VMM.
///
/// This is experimental. There is an infinite number of DTBs corresponding to a
/// given device tree. For example the strings list can be in any order, and
/// NOPs can be inserted anywhere. libfdt also has non-zero padding bytes and
/// trailing non-zero bytes (we only support a patched libfdt that avoids
/// those). The operations we can perform on the DTB are limited, because we
/// don't support rewriting the strings block at the moment. To do that we'd
/// need to emulate exactly the strings allocation algorithm from the DTB
/// generator.
///
/// So this is very fragile, and to obtain reliable measurements you should
/// instead load a pre-generated DTB into the Realm (see DTBGenerator::gen_dtb())
///
use byteorder::{BigEndian, ReadBytesExt};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::io::BufRead;

// Note that this file uses a lot of extra features from vm_fdt that aren't yet
// upstream (and may never be!)
use vm_fdt::{FdtReserveEntry, FdtWriter};

#[derive(Debug, thiserror::Error)]
/// Errors associated with creating the Flattened Device Tree.
pub enum DTBError {
    /// I/O error
    #[error("I/O")]
    IO(#[from] std::io::Error),

    /// writer error
    #[error("FDT writer")]
    FdtWriter(#[from] vm_fdt::Error),

    /// parse error: offset out of bounds
    #[error("offset is out of bounds")]
    OutOfBounds,

    /// unimplemented feature
    #[error("unimplemented: {0}")]
    Unimplemented(String),

    /// parse error
    #[error("parsing: {0}")]
    Parse(String),

    /// encoding error
    #[error("invalid name encoding")]
    Encoding,
}
/// A Result with DTBError
pub type DTBResult<T> = core::result::Result<T, DTBError>;
type Result<T> = DTBResult<T>;

const FDT_MAGIC: u32 = 0xd00dfeed;
const FDT_BEGIN_NODE: u32 = 0x00000001;
const FDT_END_NODE: u32 = 0x00000002;
const FDT_PROP: u32 = 0x00000003;
const FDT_NOP: u32 = 0x00000004;
const FDT_END: u32 = 0x00000009;

/// Take a DTB template as input, and output a similar DTB with modified nodes.
/// The implementation filters the nodes that need modifications and replaces
/// them with compatible ones.
///
/// The template should have all possible nodes, no more and no less, because
/// the strings table that contains property names cannot be modified at the
/// moment.
pub trait DTBSurgeon {
    /// Handle one node in the tree. Return true if handled, false otherwise.
    /// If this function does not handle the node, then update_dtb() adds the
    /// node to the FdtWriter, and continues iterating over its children and
    /// properties. When handling the node this function may discard it or
    /// replace it with one or more nodes by calling FdtWriter methods directly.
    fn handle_node(&self, _fdt: &mut FdtWriter, _node_name: &str) -> Result<bool> {
        Ok(false)
    }

    /// Handle one property. Return true if handled, false otherwise. If this
    /// function does not handle the property, then update_dtb() adds it to
    /// to the FdtWriter. When handling the property this function may discard
    /// it or replace it with one or more property by calling FdtWriter methods
    /// directly.
    fn handle_property(
        &self,
        fdt: &mut FdtWriter,
        node_name: &str,
        property_name: &str,
        property_val: &[u8],
    ) -> Result<bool> {
        self.handle_property_common(fdt, node_name, property_name, property_val)
    }

    /// Base guest-physical address and size of RAM
    fn mem(&self) -> (u64, u64);

    /// Base guest-physical address and size of initrd, if enabled.
    fn initrd(&self) -> Option<(u64, u64)>;

    /// Kernel parameters, if any
    fn bootargs(&self) -> Option<&str>;

    /// handle_property() implementation for some common properties
    fn handle_property_common(
        &self,
        fdt: &mut FdtWriter,
        node_name: &str,
        property_name: &str,
        _property_val: &[u8],
    ) -> Result<bool> {
        let name = node_name.split('@').next().unwrap_or("");
        match name {
            "memory" => {
                if property_name == "reg" {
                    let (base, size) = self.mem();
                    fdt.property_array_u64("reg", &[base, size])?;
                    return Ok(true);
                }
            }
            "chosen" => match property_name {
                "linux,initrd-start" => {
                    if let Some((base, _)) = self.initrd() {
                        fdt.property_u64("linux,initrd-start", base)?;
                    }
                    return Ok(true);
                }
                "linux,initrd-end" => {
                    if let Some((base, size)) = self.initrd() {
                        fdt.property_u64("linux,initrd-end", base + size)?;
                    }
                    return Ok(true);
                }
                "bootargs" => {
                    if let Some(bootargs) = self.bootargs() {
                        fdt.property_string("bootargs", bootargs)?;
                    }
                    return Ok(true);
                }
                _ => (),
            },
            _ => (),
        }
        Ok(false)
    }

    /// Parse the input DTB template, and rewrite some of it using the
    /// handle_property() and handle_node() callbacks.
    fn update_dtb(&self, input: &[u8]) -> Result<Vec<u8>> {
        update_dtb(input, self)
    }
}

/// NOP implementation of the DTB surgeon
#[derive(Debug)]
pub struct DefaultDTBSurgeon {}
impl DTBSurgeon for DefaultDTBSurgeon {
    fn mem(&self) -> (u64, u64) {
        panic!()
    }

    /// Base guest-physical address and size of initrd, if enabled.
    fn initrd(&self) -> Option<(u64, u64)> {
        None
    }

    /// Kernel parameters, if any
    fn bootargs(&self) -> Option<&str> {
        None
    }

    fn handle_property(
        &self,
        _fdt: &mut FdtWriter,
        _node_name: &str,
        _property_name: &str,
        _property_val: &[u8],
    ) -> Result<bool> {
        Ok(false)
    }
}

enum Token<'a> {
    BeginNode(String),
    EndNode,
    Property { name: String, value: &'a [u8] },
    Nop,
    End,
}

// Parse a DTB, modify it, and write it. There already exists several FDT parser
// libraries, and we should use one of them. However their goal is generally to
// provide useful abstractions to read or generate the DTB, but this isn't what
// we want here. We want raw DTB values, in order to keep the exact order of
// strings, nodes, and properties.
fn update_dtb<T: DTBSurgeon + ?Sized>(input: &[u8], surgeon: &T) -> Result<Vec<u8>> {
    // Parse the header
    let mut header = input;
    let magic = header.read_u32::<BigEndian>()?;
    if magic != FDT_MAGIC {
        return Err(DTBError::Parse("invalid magic".to_string()));
    }
    let totalsize = header.read_u32::<BigEndian>()?;
    let off_dt_struct = header.read_u32::<BigEndian>()? as usize;
    let off_dt_strings = header.read_u32::<BigEndian>()? as usize;
    let off_mem_rsvmap = header.read_u32::<BigEndian>()? as usize;
    let version = header.read_u32::<BigEndian>()?;
    let last_comp_version = header.read_u32::<BigEndian>()?;
    let boot_cpuid_phys = header.read_u32::<BigEndian>()?;
    let size_dt_strings = header.read_u32::<BigEndian>()? as usize;
    let size_dt_struct = header.read_u32::<BigEndian>()? as usize;

    let header_size = 4 * 10;

    log::trace!("Size: {totalsize}");
    log::trace!("Version: {version} / {last_comp_version}");
    log::trace!("Struct: 0x{off_dt_struct:x}, {size_dt_struct}");
    log::trace!("Strings: 0x{off_dt_strings:x}, {size_dt_strings}");

    // Parse mem reservations
    let mut mem_reservations = vec![];
    let Some(mut reservation_block) = input.get(off_mem_rsvmap..) else {
        return Err(DTBError::OutOfBounds);
    };
    loop {
        let address = reservation_block.read_u64::<BigEndian>()?;
        let size = reservation_block.read_u64::<BigEndian>()?;
        if address == 0 && size == 0 {
            break;
        }

        mem_reservations.push(FdtReserveEntry::new(address, size)?)
    }
    let rsvmap_padding = off_mem_rsvmap - header_size;

    let mut fdt =
        FdtWriter::new_with_mem_reserv_padding(&mem_reservations, rsvmap_padding)?;
    fdt.set_boot_cpuid_phys(boot_cpuid_phys);
    fdt.set_version(version);
    fdt.set_last_comp_version(last_comp_version);

    let rsvmap_size = mem_reservations.len() * 16 + 16;
    let struct_padding = off_dt_struct - (off_mem_rsvmap + rsvmap_size);
    if struct_padding != 0 {
        // TODO
        return Err(DTBError::Unimplemented(format!(
            "struct padding {struct_padding}"
        )));
    }

    let strings_padding = off_dt_strings - (off_dt_struct + size_dt_struct);
    if strings_padding != 0 {
        // TODO
        return Err(DTBError::Unimplemented(format!(
            "strings padding {strings_padding}"
        )));
    }

    // Is there any padding at the end? Then it's probably a fixed size DTB. We
    // try to automatically distinguish the tight DTBs from the ones that
    // contain the whole reserved location like QEMU.
    // TODO:
    let content_size = header_size
        + rsvmap_padding
        + rsvmap_size
        + struct_padding
        + size_dt_struct
        + strings_padding
        + size_dt_strings;
    if content_size < totalsize as usize {
        log::debug!("set total size {content_size} -> {totalsize}");
        fdt.set_total_size(totalsize);
    }

    // First parse everything an create temporary nodes. We need to extract the
    // string offsets used so that they're available when we create the output
    // DTB. Although the strings are already available to us via off_dt_strings,
    // the nodes could cleverly use offsets *inside* the strings in order to
    // reuse common suffixes, like libfdt does.

    // Parse the struct block
    let mut string_offsets = BTreeMap::<CString, u32>::new();
    let mut tokens = vec![];
    let Some(mut data) = input.get(off_dt_struct..) else {
        return Err(DTBError::OutOfBounds);
    };
    loop {
        let token = data.read_u32::<BigEndian>()?;
        match token {
            FDT_BEGIN_NODE => {
                let mut name = vec![];
                let namesz = data.read_until(0, &mut name)?;
                if namesz == 0 {
                    return Err(DTBError::Parse(
                        "unexpected empty node name".to_string(),
                    ));
                }
                let name = CString::new(&name[..namesz - 1]).expect("no NUL bytes");
                let name = name.into_string().map_err(|_| DTBError::Encoding)?;

                // align to 4 bytes
                let offset = namesz % 4;
                if offset != 0 {
                    let padding = data.get(..4 - offset).ok_or(DTBError::OutOfBounds)?;
                    if padding.iter().any(|e| *e != 0) {
                        // libfdt inserts non-zero padding bytes :(
                        log::error!(" node {name:?} non-zero padding {padding:?}");
                    }
                    data = data.get(4 - offset..).ok_or(DTBError::OutOfBounds)?;
                }

                log::trace!("Begin node {name:?}");
                tokens.push(Token::BeginNode(name));
            }
            FDT_END_NODE => {
                log::trace!("End node");
                tokens.push(Token::EndNode)
            }
            FDT_PROP => {
                let len = data.read_u32::<BigEndian>()? as usize;
                let nameoff = data.read_u32::<BigEndian>()? as usize;
                let mut name = input
                    .get(off_dt_strings + nameoff..)
                    .ok_or(DTBError::OutOfBounds)?;

                let mut name_bytes = vec![];
                let namesz = name.read_until(0, &mut name_bytes)?;
                if namesz == 0 {
                    return Err(DTBError::OutOfBounds);
                }
                let name = CString::new(&name_bytes[..namesz - 1]).expect("no NUL bytes");
                log::trace!(" prop {name:?} (nameoff 0x{nameoff:x})");

                tokens.push(Token::Property {
                    name: name.clone().into_string().map_err(|_| DTBError::Encoding)?,
                    value: &data[..len],
                });

                string_offsets.insert(name.clone(), nameoff as u32);

                data = &data[len..];
                // align to 4 bytes
                let offset = len % 4;
                if offset != 0 {
                    let padding = data.get(..4 - offset).ok_or(DTBError::OutOfBounds)?;
                    if padding.iter().any(|e| *e != 0) {
                        log::error!(" prop {name:?} non-zero padding {padding:?}");
                    }
                    data = data.get(4 - offset..).ok_or(DTBError::OutOfBounds)?;
                }
            }
            FDT_NOP => tokens.push(Token::Nop),
            FDT_END => {
                tokens.push(Token::End);
                break;
            }
            _ => return Err(DTBError::Parse(format!("unexpected token 0x{token:x}"))),
        }
    }

    // Parse the string block
    let mut strings = BTreeMap::<u32, CString>::new();
    let mut strings_block = input.get(off_dt_strings..).ok_or(DTBError::OutOfBounds)?;
    let mut nameoff = 0;
    loop {
        let mut name_bytes = vec![];
        let namesz = strings_block.read_until(0, &mut name_bytes)?;
        if namesz == 0 {
            return Err(DTBError::OutOfBounds);
        }
        let cstr = CString::new(&name_bytes[..namesz - 1]).expect("no NUL bytes");
        strings.insert(
            nameoff
                .try_into()
                .map_err(|_| DTBError::Parse("name size overflow".to_string()))?,
            cstr,
        );
        nameoff += namesz;
        if nameoff == size_dt_strings {
            break;
        }
        assert!(nameoff < size_dt_strings);
    }
    let values: Vec<CString> = strings.values().cloned().collect();
    fdt.add_strings(string_offsets, values)?;

    // Now we have everything we need to recreate the tree.
    let mut nodes = vec![];
    let mut ignore_node: usize = 0;
    let mut current_node_token = None;
    for token in tokens {
        match token {
            Token::BeginNode(name) => {
                if ignore_node > 0 {
                    ignore_node += 1;
                    continue;
                }

                match surgeon.handle_node(&mut fdt, &name) {
                    Ok(true) => ignore_node += 1,
                    Ok(false) => {
                        let new_node = fdt.begin_node(&name)?;
                        nodes.push(new_node);
                        current_node_token = Some(name);
                    }
                    Err(e) => return Err(e),
                }
            }
            Token::EndNode => {
                if ignore_node > 0 {
                    ignore_node -= 1;
                    continue;
                }

                let Some(node) = nodes.pop() else {
                    return Err(DTBError::Parse("unexpected end node".to_string()));
                };

                fdt.end_node(node)?;
            }
            Token::Property { name, value } => {
                if ignore_node > 0 {
                    continue;
                }
                let Some(node_name) = &current_node_token else {
                    return Err(DTBError::Parse("unexpected property".to_string()));
                };
                match surgeon.handle_property(&mut fdt, node_name, &name, value) {
                    Ok(true) => continue,
                    Ok(false) => {
                        fdt.property(&name, value)?;
                    }
                    Err(e) => return Err(e),
                }
            }
            Token::Nop => {
                if ignore_node > 0 {
                    continue;
                }
                // TODO: add this to output DTB
                return Err(DTBError::Unimplemented("NOP".to_string()));
            }
            Token::End => {
                break;
            }
        }
    }

    Ok(fdt.finish()?)
}