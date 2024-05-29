// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

mod hash;

use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};
use hash::HashAlgorithm;
use serde_json::{Map, Value};
use sha2::{digest::FixedOutput, Digest, Sha256, Sha384, Sha512};

#[derive(Clone)]
pub struct AAEvent {
    pub domain: String,
    pub operation: String,
    pub content: String,
}

impl FromStr for AAEvent {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        let input_trimed = input.trim_end();
        let sections: Vec<&str> = input_trimed.split(' ').collect();
        if sections.len() != 3 {
            bail!("Illegal AA event entry format. Should be `<domain> <operation> <content>`");
        }
        Ok(Self {
            domain: sections[0].into(),
            operation: sections[1].into(),
            content: sections[2].into(),
        })
    }
}

#[derive(Clone)]
pub struct AAEventlog {
    pub hash_algorithm: HashAlgorithm,
    pub init_state: Vec<u8>,
    pub events: Vec<AAEvent>,
}

impl FromStr for AAEventlog {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        let all_lines = input.lines().collect::<Vec<&str>>();

        let (initline, eventlines) = all_lines
            .split_first()
            .ok_or(anyhow!("at least one line should be included in AAEL"))?;

        // Init line looks like
        // INIT sha256/0000000000000000000000000000000000000000000000000000000000000000
        let init_line_items = initline.split_ascii_whitespace().collect::<Vec<&str>>();
        if init_line_items.len() != 2 {
            bail!("Illegal INIT event record.");
        }

        if init_line_items[0] != "INIT" {
            bail!("INIT event should start with `INIT` key word");
        }

        let (hash_algorithm, init_state) = init_line_items[1].split_once('/').ok_or(anyhow!(
            "INIT event should have `<sha-algorithm>/<init-PCR-value>` as content after `INIT`"
        ))?;

        let hash_algorithm = hash_algorithm
            .try_into()
            .context("parse Hash Algorithm in INIT entry")?;
        let init_state = hex::decode(init_state).context("parse init state in INIT entry")?;

        let events = eventlines
            .iter()
            .map(|line| AAEvent::from_str(line))
            .collect::<Result<Vec<AAEvent>>>()?;

        Ok(Self {
            events,
            hash_algorithm,
            init_state,
        })
    }
}

impl AAEventlog {
    fn accumulate_hash<D: Digest + FixedOutput>(&self) -> Vec<u8> {
        let mut state = self.init_state.clone();

        let mut init_event_hasher = D::new();
        let init_event = format!(
            "INIT {}/{}",
            self.hash_algorithm.as_ref(),
            hex::encode(&self.init_state)
        );
        Digest::update(&mut init_event_hasher, init_event.as_bytes());
        let init_event_hash = init_event_hasher.finalize();

        let mut hasher = D::new();
        Digest::update(&mut hasher, &state);

        Digest::update(&mut hasher, init_event_hash);
        state = hasher.finalize().to_vec();

        self.events.iter().for_each(|event| {
            let mut event_hasher = D::new();
            Digest::update(&mut event_hasher, event.domain.as_bytes());
            Digest::update(&mut event_hasher, b" ");
            Digest::update(&mut event_hasher, event.operation.as_bytes());
            Digest::update(&mut event_hasher, b" ");
            Digest::update(&mut event_hasher, event.content.as_bytes());
            let event_hash = event_hasher.finalize();

            let mut hasher = D::new();
            Digest::update(&mut hasher, &state);
            Digest::update(&mut hasher, event_hash);
            state = hasher.finalize().to_vec();
        });

        state
    }

    /// Check the integrity of the AAEL, and gets a digest. The digest should be the same
    /// as the input `rtmr`, or the integrity check will fail.
    pub fn integrity_check(&self, rtmr: &[u8]) -> Result<()> {
        let result = match self.hash_algorithm {
            HashAlgorithm::Sha256 => self.accumulate_hash::<Sha256>(),
            HashAlgorithm::Sha384 => self.accumulate_hash::<Sha384>(),
            HashAlgorithm::Sha512 => self.accumulate_hash::<Sha512>(),
        };

        if rtmr != result {
            bail!(
                "AA eventlog does not pass check. AAEL value : {}, Quote value {}",
                hex::encode(result),
                hex::encode(rtmr)
            );
        }

        Ok(())
    }

    pub fn to_parsed_claims(&self) -> Map<String, Value> {
        let mut aael = Map::new();
        for eventlog in &self.events {
            let key = format!("{}/{}", eventlog.domain, eventlog.operation);
            let item = Value::String(eventlog.content.clone());
            match aael.get_mut(&key) {
                Some(value) => value
                    .as_array_mut()
                    .expect("Only array can be inserted")
                    .push(item),
                None => {
                    // This insertion will ensure the value in AAEL always be
                    // `Array`s. This will make `as_array_mut()` always result
                    // in `Some`.
                    aael.insert(key, Value::Array(vec![item]));
                }
            }
        }

        aael
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use rstest::rstest;

    #[rstest]
    #[case("./test_data/aael/AAEL_data_1", b"71563a23b430b8637970b866169052815ef9434056516dc9f78c1b3bfb745cee18a2ca92aa53c8122be5cbe59a100764")]
    #[case("./test_data/aael/AAEL_data_2", b"31fa17881137923029b1da5b368e92d8b22b14bbb4deaa360da61fce7aa530bd2f4c59ac7bd27021ef64104ff4dd04f9")]
    #[case("./test_data/aael/AAEL_data_3", b"0de62b45b29775495d278c85ad63ff45e59406e509506b26c545a5419316e1c4bd2b00a4e803051fa98b550767e13f06")]
    fn aael_integrity_check(#[case] aael_path: &str, #[case] sum: &[u8]) {
        use std::str::FromStr;

        use super::AAEventlog;

        let aael_bin = fs::read_to_string(aael_path).unwrap();
        let aael = AAEventlog::from_str(&aael_bin).unwrap();
        let sum = hex::decode(sum).unwrap();
        aael.integrity_check(&sum).unwrap();
    }
}
