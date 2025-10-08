use dirs::home_dir;
use nix::unistd::Uid;
use std::path::PathBuf;

/// default_base_path calculates a default base folder for Trustee according to the current user.
///
/// - `/opt/confidential-containers/` remains the base path when running as root.
/// - `$HOME/.trustee` for all users other than root.
pub fn default_base_path() -> PathBuf {
    if Uid::effective().is_root() {
        "/opt/confidential-containers".into()
    } else {
        home_dir().unwrap_or_default().join(".trustee")
    }
}
