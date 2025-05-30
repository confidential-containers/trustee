use crate::eventlog::ccel::parser::DescriptionParser;
use crate::eventlog::ccel::EventDetails;
use anyhow::{Error, Result};
pub struct SimpleStringParser;

impl DescriptionParser for SimpleStringParser {
    fn parse_description(&self, data: Vec<u8>) -> Result<EventDetails, Error> {
        let length = data[0] as usize;
        let description_bytes = &data[1..1 + length];
        let event_desc = String::from_utf8(description_bytes.to_vec())?.replace('\0', "");
        Ok(EventDetails::from_string(event_desc))
    }
}
