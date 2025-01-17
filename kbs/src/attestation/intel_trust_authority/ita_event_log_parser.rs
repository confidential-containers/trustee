use anyhow::Context;
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine};
use eventlog_rs::Eventlog;
use eventlog_rs::EventlogEntry;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Serialize, Debug)]
pub struct Rtmr {
    index: u32,
    bank: String,
}

#[derive(Serialize, Debug)]
pub struct RtmrEvent {
    type_id: String,
    type_name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
    measurement: String,
}

#[derive(Serialize, Debug)]
pub struct RtmrLog {
    rtmr: Rtmr,
    rtmr_events: Vec<RtmrEvent>,
}

#[derive(Clone, Hash, Eq, PartialEq)]
pub struct MrIndex {
    pub index: u32,
    pub sha: String,
}

pub struct CcEventLogParser;

impl CcEventLogParser {
    pub fn handle(encoded_event_log: String) -> Result<String> {
        let decoded_event_log = STANDARD
            .decode(encoded_event_log)
            .context("Failed to decode base64 encoded event log")?;

        let event_log = Eventlog::try_from(decoded_event_log)
            .context("Failed to decode event log from given data.")?;

        let json = serde_json::to_string(&Self::parse(&event_log.log))
            .context("Failed to serialize parsed event log in ITA format.")?;

        Ok(STANDARD.encode(json))
    }

    pub fn parse(data: &Vec<EventlogEntry>) -> Vec<RtmrLog> {
        let mut event_logs_by_mr_index: HashMap<MrIndex, Vec<EventlogEntry>> = HashMap::new();

        for log_entry in data.iter() {
            let index = MrIndex {
                index: log_entry.target_measurement_registry,
                sha: log_entry.digests[0]
                    .algorithm
                    .clone()
                    .replace("TPM_ALG_", ""),
            };
            match event_logs_by_mr_index.get_mut(&index) {
                Some(logs) => logs.push(log_entry.clone()),
                None => {
                    event_logs_by_mr_index.insert(index, vec![log_entry.clone()]);
                }
            }
        }

        let mut out_logs = Vec::new();

        for (mr_index, log_set) in event_logs_by_mr_index.iter() {
            let index = mr_index.index;
            let bank = mr_index.sha.clone();

            let mut events = Vec::new();

            for event_entry in log_set.clone() {
                let type_name = event_entry.event_type;
                let mut tags = Vec::new();

                if let Ok(valid_utf8) = String::from_utf8(event_entry.event_desc.clone()) {
                    if !valid_utf8.contains('\u{0000}') {
                        tags.push(valid_utf8);
                    }
                }

                let type_id = format!("0x{:08X}", event_entry.event_type_id);
                let measurement = hex::encode(event_entry.digests[0].digest.clone());
                events.push(RtmrEvent {
                    type_id,
                    type_name,
                    tags,
                    measurement,
                });
            }

            out_logs.push(RtmrLog {
                rtmr: Rtmr { index, bank },
                rtmr_events: events,
            });
        }

        out_logs
    }
}
