use serde::{Deserialize, Serialize};

pub type TeeEvidenceParsedClaim = serde_json::Value;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SetPolicyInput {
    pub r#type: String,
    pub policy_id: String,
    pub policy: String,
}
