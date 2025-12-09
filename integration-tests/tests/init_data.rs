// Copyright (c) 2025 by NVIDIA.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use log::info;
use serde_json::json;
use serial_test::serial;
use sha2::{Digest, Sha256};

extern crate integration_tests;
use crate::integration_tests::common::{KbsConfigType, PolicyType, TestHarness};

const SECRET_BYTES: &[u8; 8] = b"shhhhhhh";
const SECRET_PATH: &str = "default/test/secret";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
// Check if we can set a policy that expects a particular init-data hash
// and get a resource.
async fn get_resource_with_init_data_hash() -> Result<()> {
    let _ = env_logger::try_init_from_env(env_logger::Env::new().default_filter_or("debug"));

    let harness = TestHarness::new(KbsConfigType::EarTokenBuiltInRvps.into()).await?;

    // Set Secret
    info!("TEST: setting secret");
    harness
        .set_secret(SECRET_PATH.to_string(), SECRET_BYTES.to_vec())
        .await?;

    // Set Policy
    let policy = policy_with_init_data_hash(SIMPLE_INIT_DATA.to_string())?;

    info!("TEST: policy with init-data hash: {policy}");

    // The PolicyType enum is static so that it can be used in the rstest macro.
    // This policy needs to be generated dynamically.
    let static_policy: &'static str = Box::leak(policy.into_boxed_str());

    info!("TEST: setting policy");
    harness
        .set_policy(PolicyType::Custom(static_policy))
        .await?;

    // Get Secret
    info!("TEST: getting secret");
    let res = harness
        .get_secret(SECRET_PATH.to_string(), Some(SIMPLE_INIT_DATA.to_string()))
        .await;

    harness.cleanup().await?;

    if res? != SECRET_BYTES {
        bail!("Secret retrieved, but secret has wrong value");
    }
    Ok(())
}

fn policy_with_init_data_hash(init_data: String) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(init_data.as_bytes());

    let hash_bytes = hasher.finalize();
    let init_data_hash = STANDARD.encode(hash_bytes);

    let policy = INIT_DATA_HASH_POLICY.replace("{init_data_hash}", &init_data_hash);

    Ok(policy)
}

const INIT_DATA_HASH_POLICY: &str = "
package policy
import rego.v1

default allow = false

allow if {
    input[\"submods\"][\"cpu0\"][\"ear.veraison.annotated-evidence\"][\"init_data\"] == \"{init_data_hash}\"
}
";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
// Use a policy that checks a particular field of the CDH/AA config.
async fn get_resource_with_init_data_config() -> Result<()> {
    let _ = env_logger::try_init_from_env(env_logger::Env::new().default_filter_or("debug"));

    let harness = TestHarness::new(KbsConfigType::EarTokenBuiltInRvps.into()).await?;

    // Set Secret
    info!("TEST: setting secret");
    harness
        .set_secret(SECRET_PATH.to_string(), SECRET_BYTES.to_vec())
        .await?;

    // Set Policy
    info!("TEST: setting policy");
    harness
        .set_policy(PolicyType::Custom(INIT_DATA_CONFIG_FIELD_POLICY))
        .await?;

    // Get Secret
    info!("TEST: getting secret");
    let res = harness
        .get_secret(SECRET_PATH.to_string(), Some(SIMPLE_INIT_DATA.to_string()))
        .await;

    harness.cleanup().await?;

    if res? != SECRET_BYTES {
        bail!("Secret retrieved, but secret has wrong value");
    }
    Ok(())
}

const INIT_DATA_CONFIG_FIELD_POLICY: &str = "
package policy
import rego.v1

default allow = false

allow if {
    input[\"submods\"][\"cpu0\"][\"ear.veraison.annotated-evidence\"][\"init_data_claims\"][\"cdh.toml\"][\"image\"][\"extra_root_certificates\"][0] == \"-----BEGIN CERTIFICATE-----\\nMIIFTDCCAvugAwIBAgIBADBGBgkqhkiG9w0BAQowOaAPMA0GCWCGSAFlAwQCAgUA\\noRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAgUAogMCATCjAwIBATB7MRQwEgYD\\nVQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxFDASBgNVBAcMC1NhbnRhIENs\\nYXJhMQswCQYDVQQIDAJDQTEfMB0GA1UECgwWQWR2YW5jZWQgTWljcm8gRGV2aWNl\\n-----END CERTIFICATE-----\\n\"
}
";

const SIMPLE_INIT_DATA: &str = "
version = \"0.1.0\"
algorithm = \"sha256\"
[data]
\"policy.rego\" = '''
package agent_policy

default AddARPNeighborsRequest := true
default AddSwapRequest := true
default CloseStdinRequest := true
default CopyFileRequest := true
default CreateContainerRequest := true
default CreateSandboxRequest := true
default DestroySandboxRequest := true
default ExecProcessRequest := true
default GetMetricsRequest := true
default GetOOMEventRequest := true
default GuestDetailsRequest := true
default ListInterfacesRequest := true
default ListRoutesRequest := true
default MemHotplugByProbeRequest := true
default OnlineCPUMemRequest := true
default PauseContainerRequest := true
default PullImageRequest := true
default ReadStreamRequest := true
default RemoveContainerRequest := true
default RemoveStaleVirtiofsShareMountsRequest := true
default ReseedRandomDevRequest := true
default ResumeContainerRequest := true
default SetGuestDateTimeRequest := true
default SetPolicyRequest := true
default SignalProcessRequest := true
default StartContainerRequest := true
default StartTracingRequest := true
default StatsContainerRequest := true
default StopTracingRequest := true
default TtyWinResizeRequest := true
default UpdateContainerRequest := true
default UpdateEphemeralMountsRequest := true
default UpdateInterfaceRequest := true
default UpdateRoutesRequest := true
default WaitProcessRequest := true
default WriteStreamRequest := true
'''
\"aa.toml\" = '''
[token_configs]
[token_configs.kbs]
url = \"http://1.2.3.4:8080\"
'''

\"cdh.toml\" = '''
[kbc]
name = \"cc_kbc\"
url = \"http://1.2.3.4:8080\"

[image]
extra_root_certificates = [\"\"\"
-----BEGIN CERTIFICATE-----
MIIFTDCCAvugAwIBAgIBADBGBgkqhkiG9w0BAQowOaAPMA0GCWCGSAFlAwQCAgUA
oRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAgUAogMCATCjAwIBATB7MRQwEgYD
VQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxFDASBgNVBAcMC1NhbnRhIENs
YXJhMQswCQYDVQQIDAJDQTEfMB0GA1UECgwWQWR2YW5jZWQgTWljcm8gRGV2aWNl
-----END CERTIFICATE-----
\"\"\"]
'''
";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
// Check for a particular field in the kata agent policy claims
async fn get_resource_with_policy_init_data() -> Result<()> {
    let _ = env_logger::try_init_from_env(env_logger::Env::new().default_filter_or("debug"));

    let harness = TestHarness::new(KbsConfigType::EarTokenBuiltInRvps.into()).await?;

    // Set Secret
    info!("TEST: setting secret");
    harness
        .set_secret(SECRET_PATH.to_string(), SECRET_BYTES.to_vec())
        .await?;

    // Set Policy
    info!("TEST: setting policy");
    harness
        .set_policy(PolicyType::Custom(INIT_DATA_FOR_OPA_POLICY))
        .await?;

    // Get Secret
    info!("TEST: getting secret");
    let res = harness
        .get_secret(SECRET_PATH.to_string(), Some(POLICY_INIT_DATA.to_string()))
        .await;

    harness.cleanup().await?;

    if res? != SECRET_BYTES {
        bail!("Secret retrieved, but secret has wrong value");
    }
    Ok(())
}

const POLICY_INIT_DATA: &str = include_str!("init-data-with-policy.toml");

const INIT_DATA_FOR_OPA_POLICY: &str = "
package policy
import rego.v1

default allow = false

allow if {
    input[\"submods\"][\"cpu0\"][\"ear.veraison.annotated-evidence\"][\"init_data_claims\"][\"agent_policy_claims\"][\"containers\"][1][\"OCI\"][\"Process\"][\"Args\"][0] = \"/opt/bitnami/scripts/nginx/entrypoint.sh\"
}
";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
// Check if using initrd with a policy will result in the expected
// validated identifiers.
async fn check_validated_identifiers() -> Result<()> {
    let _ = env_logger::try_init_from_env(env_logger::Env::new().default_filter_or("debug"));

    let harness = TestHarness::new(KbsConfigType::EarTokenBuiltInRvps.into()).await?;
    harness.wait().await;

    let token_payload = harness
        .get_attestation_token_payload(Some(POLICY_INIT_DATA.to_string()))
        .await?;

    harness.cleanup().await?;

    let validated_identifiers = token_payload
        .pointer("/submods/cpu0/ear.trustee.identifiers/validated")
        .ok_or(anyhow!("Could not find validated identifiers."))?;

    let expected_identifiers =
        json!({"container_images":["bitnami/nginx:latest"],"container_uids":[65535,1001]});

    if *validated_identifiers == expected_identifiers {
        return Ok(());
    }
    bail!(
        "Unexpected identifiers\n\nExpected: {}\n\n Got: {}",
        validated_identifiers,
        expected_identifiers
    )
}
