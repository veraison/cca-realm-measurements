use byteorder::{ByteOrder, LittleEndian};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::Serialize;
use std::{collections::HashMap, convert::TryInto};
use thiserror::Error;
use uuid::Uuid;

use crate::{serialize_as_base64, EventType, ParseSettings};

fn string_from_widechar(wchar: &[u8]) -> Result<String, EventParseError> {
    let (head, wchar, tail) = unsafe { wchar.align_to::<u16>() };
    if !head.is_empty() {
        return Err(EventParseError::Unaligned);
    }
    if !tail.is_empty() {
        return Err(EventParseError::Unaligned);
    }
    let ustr = widestring::U16Str::from_slice(wchar);
    Ok(ustr
        .to_string()
        .map(|s| String::from(s.trim_end_matches('\0')))
        .map_err(|_| EventParseError::TextDecoding)?)
}

#[derive(Debug, Serialize)]
pub struct EfiVariableData {
    pub variable_guid: Uuid,
    pub name: String,
    #[serde(serialize_with = "serialize_as_base64")]
    pub data: Vec<u8>,
}

impl EfiVariableData {
    fn parse(data: &[u8]) -> Result<EfiVariableData, EventParseError> {
        let variable_guid = &data[0..16];
        let variable_guid: [u8; 16] = variable_guid.try_into().unwrap();
        let variable_guid = Uuid::from_bytes(variable_guid);
        let num_name_chars = LittleEndian::read_u64(&data[16..24]);
        let name_len = (num_name_chars * 2) as usize;
        let data_len = LittleEndian::read_u64(&data[24..32]) as usize;

        if data.len() != 16 + 8 + 8 + name_len + data_len {
            return Err(EventParseError::TooShort);
        }

        let name_data = &data[32..32 + name_len];
        let data = data[32 + name_len..].to_vec();

        let name = string_from_widechar(name_data)?;

        Ok(EfiVariableData {
            variable_guid,
            name,
            data,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "end_type", rename_all = "lowercase")]
pub enum EndOfPathType {
    EntireDevicePath,
    Instance,
}

#[derive(Debug, Serialize, FromPrimitive)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum DevicePathInfoHardDrivePartitionFormat {
    Mbr = 0x01,
    Gpt = 0x02,
}

#[derive(Debug, Serialize, FromPrimitive)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum DevicePathInfoHardDriveSignatureType {
    NoSignature = 0x00,
    MbrType = 0x01,
    Guid = 0x02,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DevicePathInfo {
    // Device types we couldn't parse
    UnknownDevice {
        device_type: u8,
        device_subtype: u8,

        #[serde(serialize_with = "serialize_as_base64")]
        data: Vec<u8>,
    },

    // Type: Device Path End
    EndOfPath(EndOfPathType),

    // Type: Hardware Device Path
    DevicePCI {
        function: u8,
        device: u8,
    },
    DeviceMemoryMapped {
        memory_type: u32,
        start_address: u64,
        end_address: u64,
    },

    // Type: ACPI Device Path
    Acpi {
        hid: u32,
        uid: u32,
    },

    // Type: Messaging Device Path

    // Type: Media Device Path
    HardDrive {
        partition_number: u32,
        partition_start: u64,
        partition_size: u64,
        #[serde(serialize_with = "serialize_as_base64")]
        partition_signature: Vec<u8>,
        partition_format: DevicePathInfoHardDrivePartitionFormat,
        signature_type: DevicePathInfoHardDriveSignatureType,
    },
    FilePath {
        path: String,
    },
}

impl DevicePathInfo {
    fn parse(
        device_type: u8,
        device_subtype: u8,
        data: &[u8],
    ) -> Result<DevicePathInfo, EventParseError> {
        match (device_type, device_subtype) {
            // Type: Device Path End
            //  Sub-type: End Entire Device Path
            (0x7F, 0xFF) => Ok(DevicePathInfo::EndOfPath(EndOfPathType::EntireDevicePath)),
            //  Sub-type: End this instance
            (0x7F, 0x01) => Ok(DevicePathInfo::EndOfPath(EndOfPathType::Instance)),

            // Type: Hardware Device Path
            //  Sub-type: PCI
            (0x01, 0x01) => {
                if data.len() != 2 {
                    return Err(EventParseError::TooShort);
                }
                Ok(DevicePathInfo::DevicePCI {
                    function: data[0],
                    device: data[1],
                })
            }

            //  Sub-type: Memory Mapped Device
            (0x01, 0x03) => {
                if data.len() != 20 {
                    return Err(EventParseError::TooShort);
                }
                Ok(DevicePathInfo::DeviceMemoryMapped {
                    memory_type: LittleEndian::read_u32(&data[0..4]),
                    start_address: LittleEndian::read_u64(&data[4..12]),
                    end_address: LittleEndian::read_u64(&data[12..20]),
                })
            }

            // Type: ACPI Device Path
            //  Sub-type: ACPI
            (0x02, 0x01) => {
                if data.len() != 8 {
                    return Err(EventParseError::TooShort);
                }
                Ok(DevicePathInfo::Acpi {
                    hid: LittleEndian::read_u32(&data[0..4]),
                    uid: LittleEndian::read_u32(&data[4..8]),
                })
            }

            // Type Media Devices
            //  Sub-type: Hard Drive
            (0x04, 0x01) => {
                if data.len() != 38 {
                    return Err(EventParseError::TooShort);
                }
                let partition_format =
                    match DevicePathInfoHardDrivePartitionFormat::from_u8(data[36]) {
                        None => return Err(EventParseError::InvalidValue),
                        Some(v) => v,
                    };
                let signature_type = match DevicePathInfoHardDriveSignatureType::from_u8(data[37]) {
                    None => return Err(EventParseError::InvalidValue),
                    Some(v) => v,
                };
                Ok(DevicePathInfo::HardDrive {
                    partition_number: LittleEndian::read_u32(&data[0..4]),
                    partition_start: LittleEndian::read_u64(&data[4..12]),
                    partition_size: LittleEndian::read_u64(&data[12..20]),
                    partition_signature: data[20..36].to_vec(),
                    partition_format,
                    signature_type,
                })
            }

            //  Sub-type: File Path
            (0x04, 0x04) => Ok(DevicePathInfo::FilePath {
                path: string_from_widechar(data)?,
            }),

            // Unknown device types
            _ => Ok(DevicePathInfo::UnknownDevice {
                device_type,
                device_subtype,
                data: data.to_vec(),
            }),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DevicePath {
    #[serde(flatten)]
    pub info: DevicePathInfo,
    pub next: Option<Box<DevicePath>>,
}

impl DevicePath {
    fn parse(data: &[u8]) -> Result<Option<DevicePath>, EventParseError> {
        if data.is_empty() {
            Ok(None)
        } else {
            let device_type = data[0];
            let device_subtype = data[1];
            let path_len = (LittleEndian::read_u16(&data[2..4]) - 4) as usize;

            let path_data = data[4..4 + path_len].to_vec();

            let next = DevicePath::parse(&data[4 + path_len..])?.map(Box::new);

            Ok(Some(DevicePath {
                info: DevicePathInfo::parse(device_type, device_subtype, &path_data)?,
                next,
            }))
        }
    }
}

#[derive(Debug, Serialize)]
pub struct EfiTableHeader {
    pub signature: u64,
    pub revision: u32,
    pub size: u32,
    // crc: u32
    pub reserved: u32,
}

impl EfiTableHeader {
    fn parse(data: &[u8]) -> Result<EfiTableHeader, EventParseError> {
        if data.len() != 24 {
            return Err(EventParseError::TooShort);
        }
        Ok(EfiTableHeader {
            signature: LittleEndian::read_u64(&data[0..8]),
            revision: LittleEndian::read_u32(&data[8..12]),
            size: LittleEndian::read_u32(&data[12..16]),
            reserved: LittleEndian::read_u32(&data[20..24]),
        })
    }
}

#[derive(Debug, Serialize)]
pub struct EfiPartitionHeader {
    #[serde(flatten)]
    pub header: EfiTableHeader,
    pub my_lba: u64,
    pub alternate_lba: u64,
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    pub disk_guid: Uuid,
    pub partition_entry_lba: u64,
    #[serde(serialize_with = "serialize_as_base64")]
    pub reserved: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct EfiPartitionEntry {
    pub partition_type: Uuid,
    pub unique_partition_guid: Uuid,
    pub starting_lba: u64,
    pub ending_lba: u64,
    pub attributes: u64,
    pub partition_name: String,
    #[serde(serialize_with = "serialize_as_base64")]
    pub reserved: Vec<u8>,
}

fn parse_uuid(data: &[u8]) -> Result<Uuid, EventParseError> {
    if data.len() != 16 {
        return Err(EventParseError::TooShort);
    }

    // The Microsoft GUID format is.... silly
    let data1 = LittleEndian::read_u32(&data[0..4]);
    let data2 = LittleEndian::read_u16(&data[4..6]);
    let data3 = LittleEndian::read_u16(&data[6..8]);
    let data4 = &data[8..16];

    Ok(Uuid::from_fields(data1, data2, data3, data4)?)
}

impl EfiPartitionEntry {
    fn parse(data: &[u8]) -> Result<EfiPartitionEntry, EventParseError> {
        if data.len() < 128 {
            return Err(EventParseError::TooShort);
        }

        Ok(EfiPartitionEntry {
            partition_type: parse_uuid(&data[0..16])?,
            unique_partition_guid: parse_uuid(&data[16..32])?,
            starting_lba: LittleEndian::read_u64(&data[32..40]),
            ending_lba: LittleEndian::read_u64(&data[40..48]),
            attributes: LittleEndian::read_u64(&data[48..56]),
            partition_name: string_from_widechar(&data[56..128])?,
            reserved: data[128..].to_vec(),
        })
    }
}

fn parse_efi_partition_data(
    data: &[u8],
) -> Result<(EfiPartitionHeader, Vec<EfiPartitionEntry>), EventParseError> {
    if data.len() < 24 + 64 {
        return Err(EventParseError::TooShort);
    }

    let table_header = EfiTableHeader::parse(&data[0..24])?;

    if table_header.signature != 0x5452415020494645 {
        return Err(EventParseError::InvalidSignature);
    }
    if table_header.revision != 0x00010000 {
        return Err(EventParseError::InvalidValue);
    }
    if data.len() < (table_header.size as usize) {
        return Err(EventParseError::TooShort);
    }

    let size_of_partition_entry = LittleEndian::read_u32(&data[84..88]) as usize;

    let mut header_end = data.len();
    while header_end > size_of_partition_entry + (table_header.size as usize) {
        header_end -= size_of_partition_entry;
    }

    let header = EfiPartitionHeader {
        header: table_header,
        my_lba: LittleEndian::read_u64(&data[24..32]),
        alternate_lba: LittleEndian::read_u64(&data[32..40]),
        first_usable_lba: LittleEndian::read_u64(&data[40..48]),
        last_usable_lba: LittleEndian::read_u64(&data[48..56]),
        disk_guid: parse_uuid(&data[56..72])?,
        partition_entry_lba: LittleEndian::read_u64(&data[72..80]),
        reserved: data[92..header_end].to_vec(),
    };

    let mut partitions = Vec::new();

    for offset in (header_end..data.len()).step_by(size_of_partition_entry) {
        partitions.push(EfiPartitionEntry::parse(
            &data[offset..offset + size_of_partition_entry],
        )?);
    }

    Ok((header, partitions))
}

#[derive(Debug, Serialize)]
pub enum SeparatorType {
    ConventionalBIOS,
    UEFI,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ParsedEventData {
    FirmwareBlobLocation {
        base: u64,
        length: u64,
    },
    Text(String),
    EfiVariable(EfiVariableData),
    ImageLoadEvent {
        image_location_in_memory: u64,
        image_length_in_memory: u64,
        image_link_time_address: u64,
        device_path: Option<DevicePath>,
        #[serde(serialize_with = "serialize_as_base64")]
        extra_data: Vec<u8>,
    },
    GptInfo {
        header: EfiPartitionHeader,
        partitions: Vec<EfiPartitionEntry>,
    },
    ValidSeparator(SeparatorType),
}

#[derive(Error, Debug, Serialize)]
pub enum EventParseError {
    #[error("Text decoding error")]
    TextDecoding,
    #[error("Contents are too short")]
    TooShort,
    #[error("Invalid structure signature")]
    InvalidSignature,
    #[error("Unsupported log version")]
    UnsupportedLog,
    #[error("A value was unaligned")]
    Unaligned,
    #[error("An invalid value was encountered")]
    InvalidValue,
    #[error("Invalid GUID: {0}")]
    InvalidGuid(String),
}

impl From<uuid::Error> for EventParseError {
    fn from(err: uuid::Error) -> EventParseError {
        EventParseError::InvalidGuid(format!("{:?}", err))
    }
}

impl ParsedEventData {
    fn parse_efi_text(mut data: &[u8], settings: &ParseSettings) -> Result<ParsedEventData, EventParseError> {
        if settings.workaround_string_00af && data[data.len()-2] == 0x00 && data[data.len()-1] == 0xaf {
            data = &data[..data.len()-1];
        }

        Ok(ParsedEventData::Text(
            std::str::from_utf8(data)
                .map_err(|_| EventParseError::TextDecoding)?
                .trim_end_matches('\0')
                .to_string(),
        ))
    }

    fn parse_efi_image_load_event(data: &[u8]) -> Result<ParsedEventData, EventParseError> {
        if data.len() < 32 {
            return Err(EventParseError::TooShort);
        }
        let image_location_in_memory = LittleEndian::read_u64(&data[0..8]);
        let image_length_in_memory = LittleEndian::read_u64(&data[8..16]);
        let image_link_time_address = LittleEndian::read_u64(&data[16..24]);
        let device_path_len = LittleEndian::read_u64(&data[24..32]) as usize;

        let device_path = DevicePath::parse(&data[32..32 + device_path_len])?;
        let extra_data = data[32 + device_path_len..].to_vec();

        Ok(ParsedEventData::ImageLoadEvent {
            image_location_in_memory,
            image_length_in_memory,
            image_link_time_address,
            device_path,
            extra_data,
        })
    }

    fn parse_efi_firmware_blob(data: &[u8]) -> Result<ParsedEventData, EventParseError> {
        if data.len() != 16 {
            return Err(EventParseError::TooShort);
        }
        let base = LittleEndian::read_u64(&data[0..8]);
        let length = LittleEndian::read_u64(&data[8..16]);
        Ok(ParsedEventData::FirmwareBlobLocation { base, length })
    }

    fn parse_gpt_event(data: &[u8]) -> Result<ParsedEventData, EventParseError> {
        let (header, partitions) = parse_efi_partition_data(data)?;

        Ok(ParsedEventData::GptInfo { header, partitions })
    }

    pub(crate) fn parse(
        event: EventType,
        data: &[u8],
        settings: &ParseSettings,
    ) -> Result<Option<ParsedEventData>, EventParseError> {
        match event {
            // EFI Events
            EventType::CrtmVersion => Ok(Some(ParsedEventData::Text(string_from_widechar(data)?))),
            EventType::EFIVariableDriverConfig
            | EventType::EFIVariableBoot
            | EventType::EFIVariableAuthority => Ok(Some(ParsedEventData::EfiVariable(
                EfiVariableData::parse(data)?,
            ))),
            EventType::PostCode | EventType::IPL | EventType::EFIAction => {
                Ok(Some(ParsedEventData::parse_efi_text(data, &settings)?))
            }
            EventType::EFIBootServicesApplication
            | EventType::EFIBootServicesDriver
            | EventType::EFIRuntimeServicesDriver => {
                Ok(Some(ParsedEventData::parse_efi_image_load_event(data)?))
            }
            EventType::EFIPlatformFirmwareBlob => {
                Ok(Some(ParsedEventData::parse_efi_firmware_blob(data)?))
            }
            EventType::EFIGptEvent => Ok(Some(ParsedEventData::parse_gpt_event(data)?)),

            // EFI Event types to do: HandoffTables
            EventType::Separator => {
                if data == [0, 0, 0, 0] {
                    Ok(Some(ParsedEventData::ValidSeparator(SeparatorType::UEFI)))
                } else if data == [0xff, 0xff, 0xff, 0xff] {
                    Ok(Some(ParsedEventData::ValidSeparator(
                        SeparatorType::ConventionalBIOS,
                    )))
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }
}

#[derive(Debug)]
pub(crate) struct EfiSpecId {
    pub(crate) platform_class: u32,
    pub(crate) spec_version_major: u8,
    pub(crate) spec_version_minor: u8,
    pub(crate) spec_errata: u8,
    pub(crate) uintn_size: u8,
    pub(crate) algo_sizes: HashMap<u16, u16>,
    pub(crate) vendor_info: Vec<u8>,
}

impl EfiSpecId {
    pub(crate) fn parse(data: &[u8]) -> Result<EfiSpecId, EventParseError> {
        if data.len() < 29 {
            return Err(EventParseError::TooShort);
        }
        let signature = &data[0..16];
        if signature
            != [
                0x53, 0x70, 0x65, 0x63, 0x20, 0x49, 0x44, 0x20, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x30,
                0x33, 0x00,
            ]
        {
            return Err(EventParseError::InvalidSignature);
        }
        let platform_class = LittleEndian::read_u32(&data[16..20]);
        let spec_version_minor = data[20];
        let spec_version_major = data[21];
        let spec_errata = data[22];
        let uintn_size = data[23];
        let num_algorithms = LittleEndian::read_u32(&data[24..28]);
        let mut algo_sizes = HashMap::new();
        for i in 0..num_algorithms {
            let i = i as usize;
            let algo_id = LittleEndian::read_u16(&data[28 + (i * 4)..28 + (i * 4) + 2]);
            let digest_size = LittleEndian::read_u16(&data[28 + (i * 4) + 2..28 + (i * 4) + 4]);
            algo_sizes.insert(algo_id, digest_size);
        }
        let offset = 28 + (num_algorithms * 4) as usize;
        let vendor_info_size = data[offset] as usize;
        if data.len() != (offset + vendor_info_size + 1) {
            return Err(EventParseError::TooShort);
        }
        let vendor_info = data[offset + 1..].to_vec();

        Ok(EfiSpecId {
            platform_class,
            spec_version_major,
            spec_version_minor,
            spec_errata,
            uintn_size,
            algo_sizes,
            vendor_info,
        })
    }
}
