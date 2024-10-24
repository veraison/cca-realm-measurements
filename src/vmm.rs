use std::fs::File;
use std::io::{Read, Seek, Write};

use crate::realm::RealmConfig;

#[derive(Debug, thiserror::Error)]
pub enum VmmError {
    #[error("invalid Linux header")]
    InvalidLinuxHeader,

    #[error("file {filename} error: {e}")]
    File { e: std::io::Error, filename: String },

    #[error("I/O error")]
    IO(#[from] std::io::Error),

    // RealmError already has a VmmError -> RealmError conversion, so this has
    // to be a string
    #[error("realm: {0}")]
    Realm(String),

    #[error("FDT")]
    Fdt(#[from] vm_fdt::Error),

    #[error("unimplemented: {0}")]
    Unimplemented(String),

    #[error("{0}")]
    Other(String),
}
/// A Result for VmmError
pub type VmmResult<T> = core::result::Result<T, VmmError>;
type Result<T> = VmmResult<T>;

pub type GuestAddress = u64;

/// The kind of Generic Interrupt Controller implemented in the VM
#[derive(Default)]
pub enum GicModel {
    /// version 3
    #[default]
    GICv3,
    /// version 4
    GICv4,
}

pub enum BlobStorage {
    File(File),
    Bytes(Vec<u8>),
}

pub struct VmmBlob {
    pub filename: Option<String>,
    pub guest_start: GuestAddress,
    // size loaded into memory, including zero-initialized data.
    // if it is None, use the file size.
    pub load_size: Option<u64>,
    pub size: u64,
    pub data: BlobStorage,
}

impl VmmBlob {
    /// Load file into a blob object
    pub fn from_file(filename: &str, guest_start: GuestAddress) -> Result<VmmBlob> {
        let filename = String::from(filename);

        let file = File::open(&filename).map_err(|e| VmmError::File {
            e,
            filename: filename.clone(),
        })?;

        Ok(VmmBlob {
            guest_start,
            size: file
                .metadata()
                .map_err(|e| VmmError::File {
                    e,
                    filename: filename.clone(),
                })?
                .len(),
            load_size: None,
            filename: Some(filename),
            data: BlobStorage::File(file),
        })
    }

    /// Load bytes into a blob object
    pub fn from_bytes(bytes: Vec<u8>, guest_start: GuestAddress) -> Result<VmmBlob> {
        Ok(VmmBlob {
            guest_start,
            size: bytes.len() as u64,
            load_size: None,
            filename: None,
            data: BlobStorage::Bytes(bytes),
        })
    }

    /// read_to_end() with some context in case of error
    // TODO: avoid large copies
    pub fn read_to_end_ctx(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        match &mut self.data {
            BlobStorage::File(f) => f.read_to_end(buf).map_err(|e| VmmError::File {
                filename: self.filename.as_ref().unwrap().to_string(),
                e,
            }),
            BlobStorage::Bytes(b) => b.as_slice().read_to_end(buf).map_err(VmmError::IO),
        }
    }
}

// From Documentation/arch/arm64/booting.rst
#[derive(Debug)]
#[repr(C)]
struct LinuxArm64Header {
    code0: u32,
    code1: u32,
    text_offset: u64,
    load_size: u64,
    flags: u64,
    res2: u64,
    res3: u64,
    res4: u64,
    magic: u32,
    res5: u32,
}

impl LinuxArm64Header {
    fn read(file: &mut File) -> std::io::Result<Self> {
        Ok(LinuxArm64Header {
            code0: read_hdr_u32(file)?,
            code1: read_hdr_u32(file)?,
            text_offset: read_hdr_u64(file)?,
            load_size: read_hdr_u64(file)?,
            flags: read_hdr_u64(file)?,
            res2: read_hdr_u64(file)?,
            res3: read_hdr_u64(file)?,
            res4: read_hdr_u64(file)?,
            magic: read_hdr_u32(file)?,
            res5: read_hdr_u32(file)?,
        })
    }
}

fn read_hdr_u32(file: &mut File) -> std::io::Result<u32> {
    let mut b = [0; 4];

    file.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_hdr_u64(file: &mut File) -> std::io::Result<u64> {
    let mut b = [0; 8];

    file.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

/// Load the kernel into a blob object
/// Only arm64 Linux is supported at the moment.
///
/// @guest_start is the address where the kernel will be loaded. A Linux image
///   adds an offset to this address.
///
pub fn load_kernel(filename: &str, guest_start: GuestAddress) -> Result<VmmBlob> {
    let mut blob = VmmBlob::from_file(filename, guest_start)?;

    let file = match &mut blob.data {
        BlobStorage::File(f) => f,
        _ => unreachable!(),
    };

    let header = LinuxArm64Header::read(file).map_err(|e| VmmError::File {
        filename: filename.to_string(),
        e,
    })?;

    // TODO: decompress a bz2 image, since QEMU supports that.
    // For now expect a decompressed image.
    if header.magic != 0x644d5241 {
        return Err(VmmError::InvalidLinuxHeader);
    }

    blob.load_size = Some(header.load_size);
    blob.guest_start += header.text_offset;

    file.rewind().map_err(|e| VmmError::File {
        e,
        filename: filename.to_string(),
    })?;
    Ok(blob)
}

/// Write generated DTB to file
pub fn write_dtb(output_dtb: &String, bytes: &[u8]) -> Result<()> {
    let mut file = File::create(output_dtb).map_err(|e| VmmError::File {
        e,
        filename: output_dtb.to_string(),
    })?;
    file.write_all(bytes).map_err(|e| VmmError::File {
        e,
        filename: output_dtb.to_string(),
    })?;
    Ok(())
}

/// Generate a device tree blob
pub trait DTBGenerator {
    /// Generate a DTB
    fn gen_dtb(&self) -> Result<Vec<u8>>;
    /// Set base and size of the initrd
    fn set_initrd(&mut self, base: GuestAddress, size: u64);
    /// Set base and size of the log
    fn set_log_location(&mut self, base: GuestAddress, size: u64);
    /// Enable or disable PMU
    fn set_pmu(&mut self, pmu: bool);
    /// Enable or disable GIC ITS
    fn set_its(&mut self, its: bool);
    /// Set kernel parameters
    fn set_bootargs(&mut self, args: &str);
    /// Set number of CPUs
    fn set_num_cpus(&mut self, num_cpus: usize);
    /// Set RAM size
    fn set_mem_size(&mut self, mem_size: u64);

    /// Add DTB to the realm, and optionally write it to file @output
    fn add_dtb(
        &self,
        output: &Option<String>,
        base: GuestAddress,
        realm: &mut RealmConfig,
    ) -> Result<()> {
        let dtb = self.gen_dtb()?;

        if let Some(filename) = output {
            write_dtb(filename, &dtb)?;
        }

        let blob = VmmBlob::from_bytes(dtb, base)?;
        realm
            .add_rim_blob(blob)
            .map_err(|e| VmmError::Realm(e.to_string()))?;
        Ok(())
    }
}
