use crate::eventlog::ccel::parser::DescriptionParser;
use crate::eventlog::ccel::EventDetails;
use anyhow::Error;

pub struct EvBlankParser;
impl DescriptionParser for EvBlankParser {
    fn parse_description(&self, _data: Vec<u8>) -> anyhow::Result<EventDetails, Error> {
        Ok(EventDetails::empty())
    }
}
