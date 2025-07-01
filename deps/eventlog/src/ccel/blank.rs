// Copyright (c) 2025 Intel Corporation.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{EventDataParser, EventDetails};
use anyhow::Result;

pub struct EvBlankParser;

/// Blank utility parser not defined in TCG specification used as default utility for unknown events.
impl EventDataParser for EvBlankParser {
    fn parse(&self, _data: Vec<u8>) -> Result<EventDetails> {
        Ok(EventDetails::empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::empty("")]
    #[case::uneven("740014")]
    #[case::even("00000000")]
    #[case::random_data("74686973697374657374")]
    fn test_blank_parser(#[case] test_data: &str) {
        let parser = EvBlankParser;
        let actual_result = parser.parse(hex::decode(test_data).unwrap());

        assert!(actual_result.is_ok());
        assert_eq!(actual_result.unwrap(), EventDetails::empty());
    }
}
