use flate2::read::GzDecoder;
use memmap2::Mmap;
use std::fmt::{self, Debug};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use crate::dtb_surgeon;
use crate::realm::RealmConfig;

#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum VmmError {
    #[error("invalid Linux header")]
    InvalidLinuxHeader,

    #[error("file {filename} error: {e}")]
    File { e: std::io::Error, filename: String },

    #[error("I/O error: {0}")]
    IO(#[from] std::io::Error),

    // RealmError already has a VmmError -> RealmError conversion, so this has
    // to be a string
    #[error("realm: {0}")]
    Realm(String),

    #[error("FDT: {0}")]
    Fdt(#[from] vm_fdt::Error),

    #[error("DTB: {0}")]
    Dtb(#[from] dtb_surgeon::DTBError),

    #[error("unimplemented: {0}")]
    Unimplemented(String),

    #[error("{0}")]
    Other(String),
}
/// A Result for VmmError
pub type VmmResult<T> = core::result::Result<T, VmmError>;
type Result<T> = VmmResult<T>;

/// A Guest Physical Address (GPA) aka. Intermediate Physical Address (IPA)
pub type GuestAddress = u64;

/// Blob stored as a file
#[derive(Debug, Default)]
pub struct BlobStorageFile {
    /// The filename
    pub name: String,
    // map and len are intialized lazily, to avoid opening unused files
    map: Option<Mmap>,
    len: Option<u64>,
}

impl BlobStorageFile {
    fn len(&mut self) -> Result<u64> {
        if let Some(len) = self.len {
            return Ok(len);
        }

        let file = File::open(&self.name).map_err(|e| VmmError::File {
            e,
            filename: self.name.to_string(),
        })?;
        self.len = Some(
            file.metadata()
                .map_err(|e| VmmError::File {
                    e,
                    filename: self.name.to_string(),
                })?
                .len(),
        );
        Ok(self.len.unwrap())
    }

    fn read(&mut self) -> Result<&[u8]> {
        if self.map.is_some() {
            return Ok(&self.map.as_ref().unwrap()[..]);
        }
        let file = File::open(&self.name).map_err(|e| VmmError::File {
            e,
            filename: self.name.to_string(),
        })?;
        // SAFETY: possible UB with concurrent modifications
        // https://docs.rs/memmap2/latest/memmap2/struct.Mmap.html#safety
        self.map = Some(unsafe { Mmap::map(&file)? });
        Ok(&self.map.as_ref().unwrap()[..])
    }
}

impl Clone for BlobStorageFile {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            len: self.len,
            map: None,
        }
    }
}

impl PartialEq for BlobStorageFile {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

/// The storage of an image loaded into the guest
#[derive(Clone, Debug, PartialEq)]
pub enum BlobStorage {
    /// A file
    File(BlobStorageFile),
    /// A buffer
    Bytes(Vec<u8>),
}

impl BlobStorage {
    /// Return a new BlobStorage for the given file. The file will be opened
    /// once its content is actually needed.
    pub fn from_file(filename: &str) -> Self {
        BlobStorage::File(BlobStorageFile {
            name: filename.to_string(),
            len: None,
            map: None,
        })
    }

    /// Size of the image (file size). Since file-based blobs are opened lazily,
    /// this function may return an error.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&mut self) -> Result<u64> {
        match self {
            BlobStorage::File(f) => f.len(),
            BlobStorage::Bytes(b) => Ok(b.len() as u64),
        }
    }

    /// Return the content of this blob. Since file-based blobs are opened
    /// lazily, this function may return an error.
    pub fn read(&mut self) -> Result<&[u8]> {
        match self {
            BlobStorage::File(f) => f.read(),
            BlobStorage::Bytes(b) => Ok(b),
        }
    }
}

impl Default for BlobStorage {
    fn default() -> Self {
        Self::Bytes(vec![])
    }
}

/// An image loaded into the guest
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VmmBlob {
    /// Base address of the image in the guest
    pub guest_start: GuestAddress,
    /// Size loaded into memory, including zero-initialized data.
    /// If it is None, use the file size.
    pub load_size: Option<u64>,
    /// Blob content
    pub storage: BlobStorage,
}

impl VmmBlob {
    /// Create a new blob
    pub fn new(storage: BlobStorage, guest_start: GuestAddress) -> Self {
        Self {
            guest_start,
            load_size: None,
            storage,
        }
    }

    /// Load file into a blob object
    pub fn from_file(filename: &str, guest_start: GuestAddress) -> Self {
        Self::new(BlobStorage::from_file(filename), guest_start)
    }

    /// Load bytes into a blob object
    pub fn from_bytes(bytes: Vec<u8>, guest_start: GuestAddress) -> Self {
        Self::new(BlobStorage::Bytes(bytes), guest_start)
    }

    /// Return the content of this blob. Since file-based blobs are opened
    /// lazily, this function may return an error.
    pub fn read(&mut self) -> Result<&[u8]> {
        self.storage.read()
    }

    /// Size of this blob. Since file-based blobs are opened lazily, this
    /// function may return an error.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&mut self) -> Result<u64> {
        self.storage.len()
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
    fn read(stream: &mut impl Read) -> std::io::Result<Self> {
        Ok(LinuxArm64Header {
            code0: read_hdr_u32(stream)?,
            code1: read_hdr_u32(stream)?,
            text_offset: read_hdr_u64(stream)?,
            load_size: read_hdr_u64(stream)?,
            flags: read_hdr_u64(stream)?,
            res2: read_hdr_u64(stream)?,
            res3: read_hdr_u64(stream)?,
            res4: read_hdr_u64(stream)?,
            magic: read_hdr_u32(stream)?,
            res5: read_hdr_u32(stream)?,
        })
    }
}

fn read_hdr_u32(stream: &mut impl Read) -> std::io::Result<u32> {
    let mut b = [0; 4];

    stream.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_hdr_u64(stream: &mut impl Read) -> std::io::Result<u64> {
    let mut b = [0; 8];

    stream.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

/// Load the kernel into a blob object
/// Only arm64 Linux is supported at the moment.
///
/// @guest_start is the address where the kernel will be loaded. A Linux image
///   adds an offset to this address.
///
pub fn load_kernel(filename: &str, guest_start: GuestAddress) -> Result<VmmBlob> {
    let mut blob = VmmBlob::from_file(filename, guest_start);

    let mut file = File::open(filename).map_err(|e| VmmError::File {
        filename: filename.to_string(),
        e,
    })?;

    let mut header = LinuxArm64Header::read(&mut file).map_err(|e| VmmError::File {
        filename: filename.to_string(),
        e,
    })?;

    if header.magic != 0x644d5241 {
        file.seek(SeekFrom::Start(0)).map_err(|e| VmmError::File {
            filename: filename.to_string(),
            e,
        })?;

        // Try decompressing a GZip file, since QEMU supports that
        let mut gz = GzDecoder::new(file);
        let mut content: Vec<u8> = vec![];

        gz.read_to_end(&mut content).map_err(|e| VmmError::File {
            filename: filename.to_string(),
            e,
        })?;

        let mut head = [0; 64];
        head.copy_from_slice(&content[..64]);
        header = LinuxArm64Header::read(&mut &head[..]).map_err(|e| VmmError::File {
            filename: filename.to_string(),
            e,
        })?;

        blob = VmmBlob::from_bytes(content, guest_start);
    }

    if header.magic != 0x644d5241 {
        return Err(VmmError::InvalidLinuxHeader);
    }

    blob.load_size = Some(header.load_size);
    blob.guest_start += header.text_offset;

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
    fn set_mem_size(&mut self, mem_size: u64) -> Result<()>;

    /// Add DTB to the realm, and optionally write it to file @output
    fn add_dtb(
        &self,
        input: &Option<String>,
        output: &Option<String>,
        base: GuestAddress,
        realm: &mut RealmConfig,
    ) -> Result<()> {
        let dtb = if let Some(filename) = input {
            std::fs::read(filename).map_err(|e| VmmError::File {
                e,
                filename: filename.to_string(),
            })?
        } else {
            self.gen_dtb()?
        };

        if let Some(filename) = output {
            write_dtb(filename, &dtb)?;
        }

        let blob = VmmBlob::from_bytes(dtb, base);
        realm
            .add_rim_blob(blob)
            .map_err(|e| VmmError::Realm(e.to_string()))?;
        Ok(())
    }

    /// Set a DTB template that can be modified with a DTBSurgeon. The
    /// DTBGenerator implementation does not have to implement this. It may only
    /// support generating a DTB from scratch.
    fn set_template(&mut self, _template: Vec<u8>) -> Result<()> {
        Err(VmmError::Unimplemented("DTB surgery".to_string()))
    }
}

impl Debug for dyn DTBGenerator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DTBGenerator")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blob_storage() {
        let mut b = BlobStorage::from_file("testdata/nonexistent-file.txt");
        let e = b.len();
        assert!(e.is_err());
        // Test our error type while where here
        let VmmError::File { e, filename } = e.as_ref().unwrap_err() else {
            panic!("invalid error, got {e:?}");
        };
        assert!(e.kind() == std::io::ErrorKind::NotFound);
        assert_eq!(filename, "testdata/nonexistent-file.txt");
        assert!(b.read().is_err());

        let mut b = BlobStorage::from_file("testdata/some-file.txt");
        let s = "This file is used to test file handling code.\n".as_bytes();
        assert_eq!(b.len().unwrap() as usize, s.len());
        assert_eq!(b.read().unwrap(), s);

        let mut b = BlobStorage::Bytes(s.to_vec());
        assert_eq!(b.len().unwrap() as usize, s.len());
        assert_eq!(b.read().unwrap(), s);

        let mut b = BlobStorage::Bytes(vec![]);
        assert_eq!(b.len().unwrap(), 0);
        assert_eq!(b.read().unwrap(), &[0; 0]);
    }

    #[test]
    fn test_linux_kernel() {
        let b = load_kernel("testdata/some-file.txt", 0x80000000);
        assert!(b.is_err());
        let VmmError::File { e, filename: _ } = b.as_ref().unwrap_err() else {
            panic!("invalid error, got {b:?}");
        };
        assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);

        let mut b = load_kernel("testdata/linux.bin", 0x80000000).unwrap();
        assert_eq!(b.len().unwrap(), 256);
        assert_eq!(b.load_size.unwrap(), 0x2d10000);
        assert_eq!(b.guest_start, 0x80000000);

        let mut b = load_kernel("testdata/linux.bin.gz", 0x80000000).unwrap();
        assert_eq!(b.len().unwrap(), 256);
        assert_eq!(b.load_size.unwrap(), 0x2d10000);
        assert_eq!(b.guest_start, 0x80000000);

        let b = load_kernel("testdata/randombytes.bin", 0x80000000);
        assert!(b.is_err());
        let VmmError::File { e, filename: _ } = b.as_ref().unwrap_err() else {
            panic!("invalid error, got {b:?}");
        };
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);

        let b = load_kernel("testdata/randombytes.bin.gz", 0x80000000);
        assert!(b.is_err());
        assert!(matches!(b, Err(VmmError::InvalidLinuxHeader)));
    }
}
