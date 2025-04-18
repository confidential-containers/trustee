use std::env;
use std::path::Path;

/// get_exe_basename returns the name the executable is running with.
fn get_exe_basename() -> Option<String> {
    let exe_name = env::args().next()?;
    let exe_basename = Path::new(&exe_name).file_name()?.to_str()?;
    Some(exe_basename.to_string())
}

/// match_alias selects and runs a cli according to the executable name.
pub fn match_alias() -> Result<(), String> {
    let alias = get_exe_basename().unwrap_or_default();

    match alias.as_str() {
        "true" => {}
        alias => return Err(format!("not a known alias: {alias}")),
    }

    Ok(())
}
