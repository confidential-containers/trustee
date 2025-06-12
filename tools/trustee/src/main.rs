use log::error;

mod cli;
mod keys_certs;

#[tokio::main]
async fn main() {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    if let Err(e) = cli::cli_default().await {
        error!("Error: {:#}", e);
        std::process::exit(1);
    }
}
