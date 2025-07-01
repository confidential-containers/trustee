use super::EventDetails;

pub mod blank;
pub mod boot_services_app;
pub mod device_paths;
pub mod efi_variable;
pub mod event_tag;
pub mod ipl;
pub mod platform_config_flags;
pub mod simple;
pub mod simple_string;
pub mod tcg_enum;

pub(crate) use blank::EvBlankParser;
pub(crate) use boot_services_app::EvBootServicesAppParser;
pub(crate) use efi_variable::EvEfiVariableParser;
pub(crate) use event_tag::EvEventTagParser;
pub(crate) use ipl::EvIplParser;
pub(crate) use platform_config_flags::EvPlatformConfigFlagsParser;
pub(crate) use simple::EvSimpleParser;
pub(crate) use simple_string::SimpleStringParser;

/// All parser implementations follow structures defined in <https://trustedcomputinggroup.org/wp-content/uploads/TCG-PC-Client-Platform-Firmware-Profile-Version-1.06-Revision-52_pub-3.pdf>
pub trait EventDataParser: Sync + Send {
    fn parse(&self, data: Vec<u8>) -> anyhow::Result<EventDetails>;
}
