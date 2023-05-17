use anyhow::*;
use std::ffi::CStr;
use std::os::raw::c_char;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct GoString {
    pub p: *const c_char,
    pub n: isize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct GoSlice {
    pub data: *const c_char,
    pub len: i64,
    pub cap: i64,
}

// Link import cgo function
#[link(name = "cgo")]
extern "C" {
    pub fn verifyGo(
        layoutPath: GoString,
        pubKeyPaths: GoSlice,
        intermediatePaths: GoSlice,
        linkDir: GoString,
        lineNormalizationc: i32,
    ) -> *mut c_char;
}

pub fn verify(
    layout_path: String,
    pub_key_paths: Vec<String>,
    intermediate_paths: Vec<String>,
    link_dir: String,
    line_normalization: bool,
) -> Result<()> {
    // Convert Rust String to GoString
    let layout_path = GoString {
        p: layout_path.as_ptr() as *const c_char,
        n: layout_path.len() as isize,
    };

    // Convert Rust Vec<String> to GoSlice of GoString
    let pub_key_paths_vec: Vec<_> = pub_key_paths
        .iter()
        .map(|arg| GoString {
            p: arg.as_ptr() as *const c_char,
            n: arg.len() as isize,
        })
        .collect();

    let pub_key_paths_goslice = GoSlice {
        data: pub_key_paths_vec.as_ptr() as *const c_char,
        len: pub_key_paths_vec.len() as i64,
        cap: pub_key_paths_vec.len() as i64,
    };

    // Convert Rust Vec<String> to GoSlice of GoString
    let intermediate_paths_vec: Vec<_> = intermediate_paths
        .iter()
        .map(|arg| GoString {
            p: arg.as_ptr() as *const c_char,
            n: arg.len() as isize,
        })
        .collect();

    let intermediate_paths_goslice = GoSlice {
        data: intermediate_paths_vec.as_ptr() as *const c_char,
        len: intermediate_paths_vec.len() as i64,
        cap: intermediate_paths_vec.len() as i64,
    };

    // Convert Rust String to C char*
    let link_dir = GoString {
        p: link_dir.as_ptr() as *const c_char,
        n: link_dir.len() as isize,
    };

    // Convert Rust bool to C int
    let line_normalization_c = line_normalization as i32;

    // Call the function exported by cgo and process the returned string
    let result_buf: *mut c_char = unsafe {
        verifyGo(
            layout_path,
            pub_key_paths_goslice,
            intermediate_paths_goslice,
            link_dir,
            line_normalization_c,
        )
    };

    let result_str: &CStr = unsafe { CStr::from_ptr(result_buf) };
    let res = result_str.to_str()?.to_string();

    if res.starts_with("Error::") {
        bail!(res);
    }

    Ok(())
}
