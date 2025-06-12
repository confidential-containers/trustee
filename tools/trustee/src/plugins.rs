use std::env;
use std::io::ErrorKind::{NotFound, PermissionDenied};
use std::process::{exit, Command};

use log::{debug, error};

const PLUGIN_PREFIX: &str = "trustee";

/// Spawns the plugin command and exits.
///
/// Returns only if the plugin is not found or it's not executable,
/// to allow to continue the CLI flow.
pub fn exec() {
    let mut args_iter = env::args();
    // skip arg0
    args_iter.next();
    let command = args_iter.next().expect("missing plugin command");
    let plugin_command = format!("{}-{}", PLUGIN_PREFIX, command);

    let command_result = Command::new(&plugin_command).args(args_iter).status();

    match command_result {
        Ok(status) => {
            let exit_code = status.code().unwrap_or(1);
            exit(exit_code)
        }
        Err(err) => {
            let kind = err.kind();
            let message = format!(
                "can't run plugin: {}: {}",
                &plugin_command,
                kind.to_string()
            );
            if kind == NotFound || kind == PermissionDenied {
                debug!("{}", &message);
            } else {
                error!("{}", &message);
                exit(1)
            }
        }
    }
}
