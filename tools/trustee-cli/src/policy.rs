use anyhow::{Context, Result};
use policy_engine::rego::Regorus;
use std::{fs, path::PathBuf};

const SAMPLE_INPUT: &str = r#"{
    "submods": {
        "cpu0": {
            "ear.trustworthiness-vector": { "executables": 2, "hardware": 3 },
            "ear.veraison.annotated-evidence": { "sample": { "productId": "validate-cli", "svn": 1 } }
        }
    }
}"#;

pub async fn validate(file: PathBuf, input: Option<PathBuf>, rule: String) -> Result<()> {
    let policy = fs::read_to_string(&file)
        .with_context(|| format!("failed to read policy file: {}", file.display()))?;

    let input_json = match input {
        Some(path) => fs::read_to_string(&path)
            .with_context(|| format!("failed to read input file: {}", path.display()))?,
        None => SAMPLE_INPUT.to_string(),
    };

    let engine = Regorus::default();
    let result = engine
        .evaluate(None, input_json, policy, vec![rule.clone()], vec![])
        .await
        .context("policy failed to compile or evaluate")?;

    println!("Policy is valid. hash={}", result.policy_hash);
    match result.eval_rules_result.get(&rule) {
        Some(Some(v)) => println!("{rule} = {v}"),
        _ => println!("{rule} = <no result>"),
    }
    Ok(())
}
