use crate::eventlog::ccel::parser::DescriptionParser;
use crate::eventlog::ccel::EventDetails;
use anyhow::{Error, Result};
pub struct EvSimpleParser;

impl DescriptionParser for EvSimpleParser {
    fn parse_description(&self, data: Vec<u8>) -> Result<EventDetails, Error> {
        let event_desc = String::from_utf8(data).unwrap_or_default();
        Ok(EventDetails::from_string(event_desc))
    }
}
