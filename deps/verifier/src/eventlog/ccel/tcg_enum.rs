use crate::eventlog::ccel::parser::parsers::*;
use crate::eventlog::ccel::parser::DescriptionParser;
use serde::Serialize;

#[repr(u32)]
#[derive(Debug, Clone, Hash, Copy, PartialEq, Eq, Serialize)]
pub enum TcgAlgorithm {
    #[serde(rename = "RSA")]
    Rsa = 0x1,
    #[serde(rename = "TDES")]
    Tdes = 0x3,
    #[serde(rename = "SHA-1")]
    Sha1 = 0x4,
    #[serde(rename = "SHA-256")]
    Sha256 = 0xB,
    #[serde(rename = "SHA-384")]
    Sha384 = 0xC,
    #[serde(rename = "SHA-512")]
    Sha512 = 0xD,
}

impl TryFrom<u32> for TcgAlgorithm {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x1 => Ok(TcgAlgorithm::Rsa),
            0x3 => Ok(TcgAlgorithm::Tdes),
            0x4 => Ok(TcgAlgorithm::Sha1),
            0xB => Ok(TcgAlgorithm::Sha256),
            0xC => Ok(TcgAlgorithm::Sha384),
            0xD => Ok(TcgAlgorithm::Sha512),
            _ => Err(()),
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcgEventType {
    EvPrebootCert = 0x0,
    EvPostCode = 0x1,
    EvUnused = 0x2,
    EvNoAction = 0x3,
    EvSeparator = 0x4,
    EvAction = 0x5,
    EvEventTag = 0x6,
    EvSCrtmContents = 0x7,
    EvSCrtmVersion = 0x8,
    EvCpuMicrocode = 0x9,
    EvPlatformConfigFlags = 0xa,
    EvTableOfDevices = 0xb,
    EvCompactHash = 0xc,
    EvIpl = 0xd,
    EvIplPartitionData = 0xe,
    EvNonhostCode = 0xf,
    EvNonhostConfig = 0x10,
    EvNonhostInfo = 0x11,
    EvOmitBootDeviceEvents = 0x12,

    // TCG EFI Platform Specification For TPM Family 1.1 or 1.2
    EvEfiEventBase = 0x80000000,
    EvEfiVariableDriverConfig = 0x80000001,
    EvEfiVariableBoot = 0x80000002,
    EvEfiBootServicesApplication = 0x80000003,
    EvEfiBootServicesDriver = 0x80000004,
    EvEfiRuntimeServicesDriver = 0x80000005,
    EvEfiGptEvent = 0x80000006,
    EvEfiAction = 0x80000007,
    EvEfiPlatformFirmwareBlob = 0x80000008,
    EvEfiHandoffTables = 0x80000009,
    EvEfiPlatformFirmwareBlob2 = 0x8000000a,
    EvEfiHandoffTables2 = 0x8000000b,
    EvEfiVariableBoot2 = 0x8000000c,
    EvEfiHcrtmEvent = 0x80000010,
    EvEfiVariableAuthority = 0x800000e0,
    EvEfiSpdmFirmwareBlob = 0x800000e1,
    EvEfiSpdmFirmwareConfig = 0x800000e2,
}

impl TryFrom<u32> for TcgEventType {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x0 => Ok(TcgEventType::EvPrebootCert),
            0x1 => Ok(TcgEventType::EvPostCode),
            0x2 => Ok(TcgEventType::EvUnused),
            0x3 => Ok(TcgEventType::EvNoAction),
            0x4 => Ok(TcgEventType::EvSeparator),
            0x5 => Ok(TcgEventType::EvAction),
            0x6 => Ok(TcgEventType::EvEventTag),
            0x7 => Ok(TcgEventType::EvSCrtmContents),
            0x8 => Ok(TcgEventType::EvSCrtmVersion),
            0x9 => Ok(TcgEventType::EvCpuMicrocode),
            0xA => Ok(TcgEventType::EvPlatformConfigFlags),
            0xB => Ok(TcgEventType::EvTableOfDevices),
            0xC => Ok(TcgEventType::EvCompactHash),
            0xD => Ok(TcgEventType::EvIpl),
            0xE => Ok(TcgEventType::EvIplPartitionData),
            0xF => Ok(TcgEventType::EvNonhostCode),
            0x10 => Ok(TcgEventType::EvNonhostConfig),
            0x11 => Ok(TcgEventType::EvNonhostInfo),
            0x12 => Ok(TcgEventType::EvOmitBootDeviceEvents),
            0x80000000 => Ok(TcgEventType::EvEfiEventBase),
            0x80000001 => Ok(TcgEventType::EvEfiVariableDriverConfig),
            0x80000002 => Ok(TcgEventType::EvEfiVariableBoot),
            0x80000003 => Ok(TcgEventType::EvEfiBootServicesApplication),
            0x80000004 => Ok(TcgEventType::EvEfiBootServicesDriver),
            0x80000005 => Ok(TcgEventType::EvEfiRuntimeServicesDriver),
            0x80000006 => Ok(TcgEventType::EvEfiGptEvent),
            0x80000007 => Ok(TcgEventType::EvEfiAction),
            0x80000008 => Ok(TcgEventType::EvEfiPlatformFirmwareBlob),
            0x80000009 => Ok(TcgEventType::EvEfiHandoffTables),
            0x8000000A => Ok(TcgEventType::EvEfiPlatformFirmwareBlob2),
            0x8000000B => Ok(TcgEventType::EvEfiHandoffTables2),
            0x8000000C => Ok(TcgEventType::EvEfiVariableBoot2),
            0x80000010 => Ok(TcgEventType::EvEfiHcrtmEvent),
            0x800000E0 => Ok(TcgEventType::EvEfiVariableAuthority),
            0x800000E1 => Ok(TcgEventType::EvEfiSpdmFirmwareBlob),
            0x800000E2 => Ok(TcgEventType::EvEfiSpdmFirmwareConfig),
            _ => Err(()),
        }
    }
}

impl TcgEventType {
    pub(crate) fn get_parser(&self) -> Box<dyn DescriptionParser> {
        match self {
            Self::EvPostCode => Box::new(EvSimpleParser),
            Self::EvSeparator => Box::new(EvBlankParser),
            Self::EvAction => Box::new(EvSimpleParser),
            Self::EvEventTag => Box::new(EvEventTagParser),
            Self::EvPlatformConfigFlags => Box::new(EvPlatformConfigFlagsParser),
            Self::EvCompactHash => Box::new(EvSimpleParser),
            Self::EvIpl => Box::new(EvIplParser),
            Self::EvOmitBootDeviceEvents => Box::new(EvSimpleParser),
            Self::EvEfiVariableDriverConfig => Box::new(EvEfiVariableParser),
            Self::EvEfiVariableBoot => Box::new(EvEfiVariableParser),
            Self::EvEfiBootServicesApplication => Box::new(EvBootServicesAppParser),
            Self::EvEfiAction => Box::new(EvSimpleParser),
            Self::EvEfiPlatformFirmwareBlob2 => Box::new(SimpleStringParser),
            Self::EvEfiHandoffTables2 => Box::new(SimpleStringParser),
            Self::EvEfiVariableBoot2 => Box::new(EvEfiVariableParser),
            Self::EvEfiVariableAuthority => Box::new(EvEfiVariableParser),
            _ => Box::new(EvBlankParser),
        }
    }

    pub(crate) fn format_name(&self) -> String {
        let name = format!("{:?}", self);

        let mut result = String::new();
        for (i, ch) in name.chars().enumerate() {
            if ch.is_uppercase() && i > 0 {
                result.push('_');
            }
            result.push(ch.to_ascii_uppercase());
        }

        result
    }
}
