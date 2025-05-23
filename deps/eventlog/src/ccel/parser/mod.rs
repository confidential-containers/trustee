use crate::EventDetails;
use anyhow::Result;

pub mod parsers;

/// All parser implementations follow structures defined in <https://trustedcomputinggroup.org/wp-content/uploads/TCG-PC-Client-Platform-Firmware-Profile-Version-1.06-Revision-52_pub-3.pdf>
pub trait EventDataParser: Sync + Send {
    fn parse(&self, data: Vec<u8>) -> Result<EventDetails>;
}
