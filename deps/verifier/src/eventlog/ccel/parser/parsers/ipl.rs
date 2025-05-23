use crate::eventlog::ccel::parser::DescriptionParser;
use crate::eventlog::ccel::{utils, EventDetails};
use anyhow::{bail, Error, Result};

pub struct EvIplParser;

impl DescriptionParser for EvIplParser {
    fn parse_description(&self, data: Vec<u8>) -> Result<EventDetails, Error> {
        if data.len() < 2 {
            bail!(
                "Data is too short: expected at least 2 bytes, got {}",
                data.len()
            );
        }
        let gce_ipl_prefix = [0x2e, 0x00];
        let event_desc: String = if gce_ipl_prefix == data[0..2] {
            utils::recover_string(&data[2..])
        } else {
            String::from_utf8(data)
                .unwrap_or_default()
                .replace('\u{0}', "")
        };
        Ok(EventDetails::from_string(event_desc))
    }
}
