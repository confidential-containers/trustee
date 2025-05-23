use super::{
    EvBlankParser, EvBootServicesAppParser, EvEfiVariableParser, EvEventTagParser, EvIplParser,
    EvPlatformConfigFlagsParser, EvSimpleParser, EventDataParser, SimpleStringParser,
};
use anyhow::anyhow;
use serde::Serialize;
use strum::{Display, EnumString};

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

impl TcgAlgorithm {
    pub(crate) fn get_digest_size(&self, alg: TcgAlgorithm) -> anyhow::Result<usize> {
        match alg {
            TcgAlgorithm::Sha1 => Ok(20),
            TcgAlgorithm::Sha256 => Ok(32),
            TcgAlgorithm::Sha384 => Ok(48),
            TcgAlgorithm::Sha512 => Ok(64),
            _ => Err(anyhow!(
                "Failed to get digest size for unsupported algorithm: {:?}",
                alg
            )),
        }
    }
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString, Display)]
pub enum TcgEventType {
    #[strum(serialize = "EV_PREBOOT_CERT")]
    EvPrebootCert = 0x0,
    #[strum(serialize = "EV_POST_CODE")]
    EvPostCode = 0x1,
    #[strum(serialize = "EV_UNUSED")]
    EvUnused = 0x2,
    #[strum(serialize = "EV_NO_ACTION")]
    EvNoAction = 0x3,
    #[strum(serialize = "EV_SEPARATOR")]
    EvSeparator = 0x4,
    #[strum(serialize = "EV_ACTION")]
    EvAction = 0x5,
    #[strum(serialize = "EV_EVENT_TAG")]
    EvEventTag = 0x6,
    #[strum(serialize = "EV_S_CRTM_CONTENTS")]
    EvSCrtmContents = 0x7,
    #[strum(serialize = "EV_S_CRTM_VERSION")]
    EvSCrtmVersion = 0x8,
    #[strum(serialize = "EV_CPU_MICROCODE")]
    EvCpuMicrocode = 0x9,
    #[strum(serialize = "EV_PLATFORM_CONFIG_FLAGS")]
    EvPlatformConfigFlags = 0xa,
    #[strum(serialize = "EV_TABLE_OF_DEVICES")]
    EvTableOfDevices = 0xb,
    #[strum(serialize = "EV_COMPACT_HASH")]
    EvCompactHash = 0xc,
    #[strum(serialize = "EV_IPL")]
    EvIpl = 0xd,
    #[strum(serialize = "EV_IPL_PARTITION_DATA")]
    EvIplPartitionData = 0xe,
    #[strum(serialize = "EV_NONHOST_CODE")]
    EvNonhostCode = 0xf,
    #[strum(serialize = "EV_NONHOST_CONFIG")]
    EvNonhostConfig = 0x10,
    #[strum(serialize = "EV_NONHOST_INFO")]
    EvNonhostInfo = 0x11,
    #[strum(serialize = "EV_OMIT_BOOT_DEVICE_EVENTS")]
    EvOmitBootDeviceEvents = 0x12,
    #[strum(serialize = "EV_EFI_EVENT_BASE")]
    EvEfiEventBase = 0x80000000,
    #[strum(serialize = "EV_EFI_VARIABLE_DRIVER_CONFIG")]
    EvEfiVariableDriverConfig = 0x80000001,
    #[strum(serialize = "EV_EFI_VARIABLE_BOOT")]
    EvEfiVariableBoot = 0x80000002,
    #[strum(serialize = "EV_EFI_BOOT_SERVICES_APPLICATION")]
    EvEfiBootServicesApplication = 0x80000003,
    #[strum(serialize = "EV_EFI_BOOT_SERVICES_DRIVER")]
    EvEfiBootServicesDriver = 0x80000004,
    #[strum(serialize = "EV_EFI_RUNTIME_SERVICES_DRIVER")]
    EvEfiRuntimeServicesDriver = 0x80000005,
    #[strum(serialize = "EV_EFI_GPT_EVENT")]
    EvEfiGptEvent = 0x80000006,
    #[strum(serialize = "EV_EFI_ACTION")]
    EvEfiAction = 0x80000007,
    #[strum(serialize = "EV_EFI_PLATFORM_FIRMWARE_BLOB")]
    EvEfiPlatformFirmwareBlob = 0x80000008,
    #[strum(serialize = "EV_EFI_HANDOFF_TABLES")]
    EvEfiHandoffTables = 0x80000009,
    #[strum(serialize = "EV_EFI_PLATFORM_FIRMWARE_BLOB2")]
    EvEfiPlatformFirmwareBlob2 = 0x8000000a,
    #[strum(serialize = "EV_EFI_HANDOFF_TABLES2")]
    EvEfiHandoffTables2 = 0x8000000b,
    #[strum(serialize = "EV_EFI_VARIABLE_BOOT2")]
    EvEfiVariableBoot2 = 0x8000000c,
    #[strum(serialize = "EV_EFI_HCRTM_EVENT")]
    EvEfiHcrtmEvent = 0x80000010,
    #[strum(serialize = "EV_EFI_VARIABLE_AUTHORITY")]
    EvEfiVariableAuthority = 0x800000e0,
    #[strum(serialize = "EV_EFI_SPDM_FIRMWARE_BLOB")]
    EvEfiSpdmFirmwareBlob = 0x800000e1,
    #[strum(serialize = "EV_EFI_SPDM_FIRMWARE_CONFIG")]
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
    pub(crate) fn get_parser(&self) -> Box<dyn EventDataParser> {
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
}
