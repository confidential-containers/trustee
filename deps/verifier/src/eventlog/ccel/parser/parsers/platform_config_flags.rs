use crate::eventlog::ccel::parser::DescriptionParser;
use crate::eventlog::ccel::EventDetails;
use anyhow::{Error, Result};
use serde::Serialize;

pub struct EvPlatformConfigFlagsParser;

#[derive(Debug, Clone, Serialize)]
pub struct EventDetail {
    pub name: String,
    pub value: Option<String>,
}

impl DescriptionParser for EvPlatformConfigFlagsParser {
    fn parse_description(&self, data: Vec<u8>) -> Result<EventDetails, Error> {
        let mut result_data = EventDetails::empty();
        let raw = String::from_utf8(data)
            .unwrap_or_default()
            .replace('\u{10}', " ");
        let map = parse_kernel_parameters(raw.clone());
        let cleaned = raw.chars().filter(|c| !c.is_control()).collect::<String>();
        result_data.string = Some(cleaned);
        result_data.data = Some(map);
        Ok(result_data)
    }
}

fn parse_kernel_parameters(kernel_parameters: String) -> Vec<String> {
    let parameters = kernel_parameters
        .split(&[' ', '\n', '\r', '\0', '\u{10}'])
        .collect::<Vec<&str>>()
        .iter()
        .filter_map(|item| {
            if item.is_empty() {
                return None;
            }

            let it = item.split_once('=');

            match it {
                Some((k, v)) => {
                    let detail = EventDetail {
                        name: k.into(),
                        value: Some(v.into()),
                    };
                    let json = serde_json::to_string(&detail).expect("Failed to encode json");
                    Some(json)
                }
                None => {
                    let detail = EventDetail {
                        name: item.to_string(),
                        value: None,
                    };
                    let json = serde_json::to_string(&detail).expect("Failed to encode json");
                    Some(json)
                }
            }
        })
        .collect();

    parameters
}

#[cfg(test)]
mod tests {
    use super::parse_kernel_parameters;

    use rstest::rstest;

    #[rstest]
    #[trace]
    #[case("", vec![])]
    #[case("name_only", vec![String::from("{\"name\":\"name_only\",\"value\":null}")])]
    #[case("a=b", vec![String::from("{\"name\":\"a\",\"value\":\"b\"}")])]
    #[case("\ra=b", vec![String::from("{\"name\":\"a\",\"value\":\"b\"}")])]
    #[case("\na=b", vec![String::from("{\"name\":\"a\",\"value\":\"b\"}")])]
    #[case("a=b\nc=d", vec![String::from("{\"name\":\"a\",\"value\":\"b\"}"), String::from("{\"name\":\"c\",\"value\":\"d\"}")])]
    #[case("a=b\n\nc=d", vec![String::from("{\"name\":\"a\",\"value\":\"b\"}"), String::from("{\"name\":\"c\",\"value\":\"d\"}")])]
    #[case("a=b\rc=d", vec![String::from("{\"name\":\"a\",\"value\":\"b\"}"), String::from("{\"name\":\"c\",\"value\":\"d\"}")])]
    #[case("a=b\r\rc=d", vec![String::from("{\"name\":\"a\",\"value\":\"b\"}"), String::from("{\"name\":\"c\",\"value\":\"d\"}")])]
    #[case("a=b\rc=d\ne=foo", vec![String::from("{\"name\":\"a\",\"value\":\"b\"}"), String::from("{\"name\":\"c\",\"value\":\"d\"}"), String::from("{\"name\":\"e\",\"value\":\"foo\"}")])]
    #[case("a=b\rc=d\nname_only\0e=foo", vec![String::from("{\"name\":\"a\",\"value\":\"b\"}"), String::from("{\"name\":\"c\",\"value\":\"d\"}"), String::from("{\"name\":\"name_only\",\"value\":null}"), String::from("{\"name\":\"e\",\"value\":\"foo\"}")])]
    #[case("foo='bar'", vec![String::from("{\"name\":\"foo\",\"value\":\"'bar'\"}")])]
    #[case("foo=\"bar\"", vec![String::from("{\"name\":\"foo\",\"value\":\"\\\"bar\\\"\"}")])]
    // // Spaces in parameter values are not supported.
    // // XXX: Note carefully the apostrophe values below!
    #[case("params_with_spaces_do_not_work='a b c'", vec![String::from("{\"name\":\"params_with_spaces_do_not_work\",\"value\":\"'a\"}"), String::from("{\"name\":\"b\",\"value\":null}"), String::from("{\"name\":\"c'\",\"value\":null}")])]
    #[case("params_with_spaces_do_not_work=\"a b c\"", vec![String::from("{\"name\":\"params_with_spaces_do_not_work\",\"value\":\"\\\"a\"}"), String::from("{\"name\":\"b\",\"value\":null}"), String::from("{\"name\":\"c\\\"\",\"value\":null}")])]
    #[case("a==", vec![String::from("{\"name\":\"a\",\"value\":\"=\"}")])]
    #[case("a==b", vec![String::from("{\"name\":\"a\",\"value\":\"=b\"}")])]
    #[case("a==b=", vec![String::from("{\"name\":\"a\",\"value\":\"=b=\"}")])]
    #[case("a=b=c", vec![String::from("{\"name\":\"a\",\"value\":\"b=c\"}")])]
    #[case("a==b==c", vec![String::from("{\"name\":\"a\",\"value\":\"=b==c\"}")])]
    #[case("module_foo=bar=baz,wibble_setting=2", vec![String::from("{\"name\":\"module_foo\",\"value\":\"bar=baz,wibble_setting=2\"}")])]
    #[case("a=b c== d=e", vec![String::from("{\"name\":\"a\",\"value\":\"b\"}"), String::from("{\"name\":\"c\",\"value\":\"=\"}"), String::from("{\"name\":\"d\",\"value\":\"e\"}")])]

    fn test_parse_kernel_parameters(#[case] params: String, #[case] result: Vec<String>) {
        let msg = format!("test: params: {:?}, result: {result:?}", &params);

        let actual_result = parse_kernel_parameters(params);

        let msg = format!("{msg}: actual result: {actual_result:?}");

        if std::env::var("DEBUG").is_ok() {
            println!("DEBUG: {msg}");
        }

        let expected_result_str = format!("{result:?}");
        let actual_result_str = format!("{actual_result:?}");

        assert_eq!(expected_result_str, actual_result_str, "{msg}");

        let result = result;
        let actual_result = actual_result;

        let expected_count = result.len();

        let actual_count = actual_result.len();

        let msg = format!("{msg}: expected_count: {expected_count}, actual_count: {actual_count}");

        assert_eq!(expected_count, actual_count, "{msg}");
    }
}
