use log::{debug, error};

mod cli;
mod keys_certs;

#[cfg(feature = "aliases")]
mod aliases;

#[cfg(feature = "plugins")]
mod plugins;

#[tokio::main]
async fn main() {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    #[cfg(feature = "aliases")]
    match aliases::match_alias() {
        Ok(_) => return, // the alias ran, nothing more to do
        Err(e) => {
            debug!("matching alias failed: {}", e)
            // keep going
        }
    }

    #[cfg(feature = "plugins")]
    // when there is no subcommand matching the CLI argument (unrecognized subcommand),
    // run the plugins
    if let Some(command) = std::env::args().nth(1) {
        if !<cli::Commands as clap::Subcommand>::has_subcommand(&command) {
            plugins::exec();
            // if no plugin matches, exec() returns and the flow continues below
        }
    }

    if let Err(e) = cli::cli_default().await {
        error!("Error: {:#}", e);
        std::process::exit(1);
    }
}
