use anyhow::{Context, Result};
use ear::TrustClaim;
use policy_engine::rego::Regorus;
use serde_json::Value;
use std::{fs, path::PathBuf};

const SAMPLE_INPUT: &str = r#"{
    "submods": {
        "cpu0": {
            "ear.trustworthiness-vector": { "executables": 2, "hardware": 3 },
            "ear.veraison.annotated-evidence": { "sample": { "productId": "validate-cli", "svn": 1 } }
        }
    }
}"#;

pub async fn validate(
    file: PathBuf,
    input: Option<PathBuf>,
    rule: String,
    ear: bool,
) -> Result<()> {
    let policy = fs::read_to_string(&file)
        .with_context(|| format!("failed to read policy file: {}", file.display()))?;

    let input_json = match input {
        Some(path) => fs::read_to_string(&path)
            .with_context(|| format!("failed to read input file: {}", path.display()))?,
        None => SAMPLE_INPUT.to_string(),
    };

    let mut rules = vec![rule.clone()];
    if ear {
        rules.push("data.policy.trust_claims".to_string());
        rules.push("data.policy.extensions".to_string());
    }

    let engine = Regorus::default();
    let result = engine
        .evaluate(None, input_json, policy, rules, vec![])
        .await
        .context("policy failed to compile or evaluate")?;

    println!("Policy is valid. hash={}", result.policy_hash);
    match result.eval_rules_result.get(&rule) {
        Some(Some(v)) => println!("{rule} = {v}"),
        _ => println!("{rule} = <no result>"),
    }

    if ear {
        check_ear_semantics(&result.eval_rules_result)?;
    }

    Ok(())
}

fn check_ear_semantics(results: &std::collections::HashMap<String, Option<Value>>) -> Result<()> {
    let mut errors = Vec::new();

    match results
        .get("data.policy.trust_claims")
        .and_then(|v| v.clone())
    {
        Some(Value::Object(claims)) => {
            for (key, value) in &claims {
                if TrustClaim::try_from(key.as_str()).is_err() {
                    errors.push(format!(
                        "unknown trust claim key '{key}' (not a valid AR4SI claim name)"
                    ));
                    continue;
                }
                match value.as_i64() {
                    Some(n) if (-128..=127).contains(&n) => {}
                    Some(n) => errors.push(format!(
                        "trust claim '{key}' value {n} is out of i8 range (-128..127)"
                    )),
                    None => errors.push(format!(
                        "trust claim '{key}' value {value} is not an integer"
                    )),
                }
            }
        }
        Some(other) => errors.push(format!(
            "data.policy.trust_claims should be an object, got: {other}"
        )),
        None => errors.push("data.policy.trust_claims is not set".to_string()),
    }

    if let Some(Some(Value::Array(extensions))) = results.get("data.policy.extensions") {
        for ext in extensions {
            let obj = ext.as_object();
            let has_name = obj.and_then(|o| o.get("name")).is_some();
            let has_key = obj
                .and_then(|o| o.get("key"))
                .and_then(|k| k.as_i64())
                .map(|k| i32::try_from(k).is_ok())
                .unwrap_or(false);
            let has_value = obj.and_then(|o| o.get("value")).is_some();
            if !(has_name && has_key && has_value) {
                errors.push(format!(
                    "extension entry missing required fields (name, key: i32, value): {ext}"
                ));
            }
        }
    }

    if errors.is_empty() {
        println!("EAR semantics: OK (trust_claims and extensions are well-formed)");
        Ok(())
    } else {
        for e in &errors {
            eprintln!("EAR semantics error: {e}");
        }
        anyhow::bail!("{} EAR semantic error(s) found", errors.len());
    }
}
