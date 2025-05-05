use std::env;

use log::debug;

mod cli;

#[cfg(feature = "aliases")]
mod aliases;

#[cfg(feature = "plugins")]
mod plugins;

#[tokio::main]
async fn main() {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    #[cfg(feature = "aliases")]
    match aliases::match_alias() {
        Ok(_) => return,
        Err(e) => {
            debug!("matching alias failed: {}", e)
        }
    }

    let cli_error = match cli::cli_default().await {
        Ok(_) => return,
        Err(e) => e,
    };

    #[cfg(feature = "plugins")]
    if env::args().count() > 1 {
        plugins::exec();
    }

    cli_error.exit()
}
