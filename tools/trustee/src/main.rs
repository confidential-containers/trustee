use log::debug;

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
        Ok(_) => return,
        Err(e) => {
            debug!("matching alias failed: {}", e)
        }
    }

    #[cfg(feature = "plugins")]
    match std::env::args().nth(1) {
        Some(command) => {
            if !<cli::Commands as clap::Subcommand>::has_subcommand(&command) {
                plugins::exec();
            }
        }
        None => {}
    }

    if let Err(e) = cli::cli_default().await {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}
