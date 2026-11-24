// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use policy_engine::rego::Regorus;

/// What a policy declares about itself, besides its verdict.
///
/// The declaration is read from the policy without any evidence. It tells the
/// broker which verifier results the policy judges and how the token entry it
/// produces is called.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDeclaration {
    pub policy_id: String,
    /// Names of the devices whose results are judged by the policy. All results
    /// with one of these names are passed to the policy together.
    pub devices: BTreeSet<String>,
    /// Name of the token entry (EAR submodule) produced by the policy.
    pub submod: String,
    /// The text of the policy.
    pub text: String,
}

impl PolicyDeclaration {
    /// The policy claim that lists the names of the devices the policy judges.
    const DEVICES_RULE: &str = "data.policy.devices";

    /// The policy claim that holds the name of the token entry the policy produces.
    const SUBMOD_RULE: &str = "data.policy.submod";

    pub fn accepts(&self, device: &str) -> bool {
        self.devices.contains(device)
    }

    pub fn from_raw_policy_text(policy_id: &str, text: &str) -> Result<Self> {
        let results = Regorus::evaluate_sync(
            None,
            "{}".to_string(),
            text.to_string(),
            vec![
                Self::DEVICES_RULE.to_string(),
                Self::SUBMOD_RULE.to_string(),
            ],
            vec![],
        )?
        .eval_rules_result;

        let devices = results.get(Self::DEVICES_RULE).and_then(Option::as_ref);
        let submod = results.get(Self::SUBMOD_RULE).and_then(Option::as_ref);

        let devices = devices
            .with_context(|| format!("Policy {policy_id} does not declare `devices`"))?
            .as_array()
            .with_context(|| format!("`devices` of policy {policy_id} is not a list"))?
            .iter()
            .map(|device| match device.as_str() {
                Some(device) if !device.is_empty() => Ok(device.to_string()),
                _ => bail!("`devices` of policy {policy_id} must only hold non-empty strings"),
            })
            .collect::<Result<BTreeSet<_>>>()?;

        if devices.is_empty() {
            bail!("`devices` of policy {policy_id} is empty, the policy would never run");
        }

        let submod = submod
            .with_context(|| format!("Policy {policy_id} does not declare `submod`"))?
            .as_str()
            .with_context(|| format!("`submod` of policy {policy_id} is not a string"))?;
        if submod.is_empty() {
            bail!("`submod` of policy {policy_id} is empty");
        }

        Ok(Self {
            policy_id: policy_id.to_string(),
            devices,
            submod: submod.to_string(),
            text: text.to_string(),
        })
    }
}
