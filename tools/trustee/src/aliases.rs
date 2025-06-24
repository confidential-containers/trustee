use std::env;
use std::path::Path;

// Aliases module for trustee CLI
//
// Aliases are intended for creating symbolic links with different names to the same binary,
// similar to how busybox works. This allows a single executable to behave differently 
// depending on the name it's invoked with.
//
// To add a new alias:
// 1. Add your logic to the match statement in `match_alias()`
// 2. Create a symbolic link to the trustee binary with your desired alias name
//
// Example alias:
// - "true": Always returns success (exit code 0), mimicking the shell command of the same name

/// get_alias_basename returns the name the program is being called with.
/// Respects symbolic links, contrary to `env::current_exe()`.
fn get_alias_basename() -> Option<String> {
    let alias_name = env::args().nth(0)?;
    let alias_basename = Path::new(&alias_name).file_name()?.to_str()?;
    Some(alias_basename.to_string())
}

/// match_alias selects and runs a cli according to the name the program is being called with.
pub fn match_alias() -> Result<(), String> {
    let alias = get_alias_basename().unwrap_or_default();

    match alias.as_str() {
        "true" => {}
        // add your new aliases here
        alias => return Err(format!("not a known alias: {alias}")),
    }

    Ok(())
}
