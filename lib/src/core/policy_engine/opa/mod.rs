use anyhow::{anyhow, Result};
use std::ffi::CStr;
use std::os::raw::c_char;

// Link import cgo function
#[link(name = "opa")]
extern "C" {
    pub fn evaluateGo(policy: GoString, data: GoString, input: GoString) -> *mut c_char;
}

/// String structure passed into cgo
#[derive(Debug)]
#[repr(C)]
pub struct GoString {
    pub p: *const c_char,
    pub n: isize,
}

pub fn evaluate(policy: String, reference: String, input: String) -> Result<String> {
    let policy_go = GoString {
        p: policy.as_ptr() as *const i8,
        n: policy.len() as isize,
    };

    let reference_go = GoString {
        p: reference.as_ptr() as *const i8,
        n: reference.len() as isize,
    };

    let input_go = GoString {
        p: input.as_ptr() as *const i8,
        n: input.len() as isize,
    };

    // Call the function exported by cgo and process the returned decision
    let decision_buf: *mut c_char = unsafe { evaluateGo(policy_go, reference_go, input_go) };
    let decision_str: &CStr = unsafe { CStr::from_ptr(decision_buf) };
    let res = decision_str.to_str()?.to_string();
    debug!("Evaluated: {}", res);
    if res.starts_with("Error::") {
        return Err(anyhow!(res));
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn dummy_reference(ver: u64) -> String {
        json!({
            "reference": {
                "productId": ver,
                "svn": ver
            }
        })
        .to_string()
    }

    fn dummy_input(product_id: u64, svn: u64) -> String {
        json!({
            "productId": product_id,
            "svn": svn
        })
        .to_string()
    }

    #[test]
    fn test_evaluate() {
        let policy = std::include_str!("../default_policy.rego").to_string();

        let res = evaluate(policy.clone(), dummy_reference(5), dummy_input(5, 5));
        assert!(res.is_ok(), "OPA execution() should be success");
        let v: Value = serde_json::from_str(&res.unwrap()).unwrap();
        assert!(v["allow"] == true, "allow should be true");

        let res = evaluate(policy.clone(), dummy_reference(5), dummy_input(0, 0));
        assert!(res.is_ok(), "OPA execution() should be success");
        let v: Value = serde_json::from_str(&res.unwrap()).unwrap();
        assert!(v["allow"] == false, "allow should be false");
    }
}
