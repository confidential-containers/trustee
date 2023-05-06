use kbs_types::Tee;
use serde::{Deserialize, Serialize};

pub type TeeEvidenceParsedClaim = serde_json::Value;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AttestationResults {
    tee: Tee,
    allow: bool,
    output: ResultOutput,
    tcb: Option<String>,
}

impl AttestationResults {
    pub fn new(
        tee: Tee,
        allow: bool,
        verifier_output: Option<String>,
        policy_engine_output: Option<String>,
        tcb: Option<String>,
    ) -> Self {
        Self {
            tee,
            allow,
            output: ResultOutput {
                verifier_output,
                policy_engine_output,
            },
            tcb,
        }
    }

    pub fn allow(&self) -> bool {
        self.allow
    }

    pub fn tee(&self) -> Tee {
        self.tee.clone()
    }

    pub fn output(&self) -> &ResultOutput {
        &self.output
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ResultOutput {
    pub verifier_output: Option<String>,
    pub policy_engine_output: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SetPolicyInput {
    pub r#type: String,
    pub policy_id: String,
    pub policy: String,
}
