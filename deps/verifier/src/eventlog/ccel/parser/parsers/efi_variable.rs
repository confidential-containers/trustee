use crate::eventlog::ccel::parser::DescriptionParser;
use crate::eventlog::ccel::{utils, EventDetails};
use anyhow::{Error, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

pub struct EvEfiVariableParser;
impl DescriptionParser for EvEfiVariableParser {
    fn parse_description(&self, data: Vec<u8>) -> Result<EventDetails, Error> {
        let mut index = 0;

        let guid: &[u8] = utils::get_next_bytes(&data, &mut index, 16)?;
        let uname_length = utils::read_u64_le(&data, &mut index)?;
        let var_data_length = utils::read_u64_le(&data, &mut index)?;

        let description_bytes =
            utils::get_next_bytes(&data, &mut index, uname_length as usize * 2)?;

        let unicode_name = String::from_utf8(description_bytes.to_vec())?.replace('\0', "");

        let mut variable_data = "".to_string();
        if var_data_length > 0 {
            let variable_data_bytes =
                utils::get_next_bytes(&data, &mut index, var_data_length as usize)?;
            variable_data = STANDARD.encode(variable_data_bytes);
        }

        Ok(EventDetails {
            string: None,
            unicode_name: Some(unicode_name),
            unicode_name_length: Some(uname_length),
            variable_data: Some(variable_data),
            variable_data_length: Some(var_data_length),
            variable_name: Some(format_guid(guid)),
            device_paths: None,
            data: None,
        })
    }
}

fn format_guid(guid: &[u8]) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        hex::encode(guid[0..4].to_vec()),
        hex::encode(guid[4..6].to_vec()),
        hex::encode(guid[6..8].to_vec()),
        hex::encode(guid[8..10].to_vec()),
        hex::encode(guid[10..16].to_vec())
    )
}
