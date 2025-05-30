use crate::eventlog::ccel::EventDetails;
use anyhow::{Error, Result};

pub mod parsers;

pub trait DescriptionParser: Sync + Send {
    fn parse_description(&self, data: Vec<u8>) -> Result<EventDetails, Error>;
}
