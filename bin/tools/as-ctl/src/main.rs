use anyhow::{anyhow, Result};
use attestation::DEFAULT_ATTESTATION_ADDR;
use clap::{Args, Parser, Subcommand};
use management::DEFAULT_MANAGEMENT_ADDR;
use shadow_rs::shadow;
use std::path::Path;

mod attestation;
mod management;

pub mod management_api {
    tonic::include_proto!("management");
}
pub mod attestation_api {
    tonic::include_proto!("attestation");
}
pub mod common {
    tonic::include_proto!("common");
}

#[macro_use]
extern crate log;
shadow!(build);

#[derive(Parser)]
#[clap(name = "as-ctl")]
#[clap(author, version, about = "A command line interface for the attestation server.", long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,

    /// The Attestation Server's `management-sock` address.
    #[clap(long, value_parser, default_value_t = String::from(DEFAULT_MANAGEMENT_ADDR))]
    addr: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Get, Set or Restore the AS evaluation `Policy(.rego)`.
    #[clap(arg_required_else_help = true)]
    Policy(Policy),

    /// Get, Set or Restore the AS evaluation `Reference Data(.json)`.
    #[clap(arg_required_else_help = true)]
    ReferenceData(ReferenceData),

    /// Test Attestation Server's `attestation` function with the input evidence file.
    #[clap(arg_required_else_help = true)]
    Attest {
        /// The evidence file path which is evaluated by Attestation Server.
        #[clap(long, value_parser)]
        evidence: String,

        /// The Attestation Server's `attestation-sock` address.
        #[clap(long, value_parser, default_value_t = String::from(DEFAULT_ATTESTATION_ADDR))]
        attest_addr: String,
    },
}

#[derive(Args)]
struct Policy {
    #[clap(subcommand)]
    command: Option<PolicyCommands>,
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Get the AS evaluation `Policy(.rego)` from Attestation Server.
    Get {
        /// Output file path to write the policy.
        #[clap(long, value_parser, default_value_t = String::from("./Policy.rego"))]
        output: String,
    },

    /// Set the AS evaluation `Policy(.rego)`.
    #[clap(arg_required_else_help = true)]
    Set {
        /// The path of local `Policy(.rego)` which will be upload to Attestation Server
        #[clap(long, value_parser)]
        policy: String,
    },

    /// Restore the Attestation Server's `Policy(.rego)` to default.
    Restore,
}

#[derive(Args)]
struct ReferenceData {
    #[clap(subcommand)]
    command: Option<ReferenceDataCommands>,
}

#[derive(Subcommand)]
enum ReferenceDataCommands {
    /// Get the `Reference Data(.json)` from Attestation Server.
    Get {
        /// Output file path to write the reference data.
        #[clap(long, value_parser, default_value_t = String::from("./Reference_data.json"))]
        output: String,
    },

    /// Set the AS evaluation `Reference Data(.json)`.
    #[clap(arg_required_else_help = true)]
    Set {
        /// The path of local `Reference Data(.json)` which will be upload to Attestation Server.
        #[clap(long, value_parser)]
        reference_data: String,
    },

    /// Restore the Attestation Server's `Reference Data(.json)` to default.
    Restore,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::builder()
        .filter(None, log::LevelFilter::Info)
        .init();

    let args = Cli::parse();

    match args.command {
        Commands::Policy(policy) => match policy.command {
            Some(PolicyCommands::Get { output }) => {
                let output_path = Path::new(&output);
                management::get_policy_cmd(output_path, &args.addr).await?;
            }
            Some(PolicyCommands::Set { policy }) => {
                let policy_path = Path::new(&policy);
                management::set_policy_cmd(policy_path, &args.addr).await?;
            }
            Some(PolicyCommands::Restore) => {
                management::restore_default_policy_cmd(&args.addr).await?;
            }
            _ => {
                return Err(anyhow!("Unsupported command, use --help for information"));
            }
        },
        Commands::ReferenceData(ref_data) => match ref_data.command {
            Some(ReferenceDataCommands::Get { output }) => {
                let output_path = Path::new(&output);
                management::get_reference_data_cmd(output_path, &args.addr).await?;
            }
            Some(ReferenceDataCommands::Set { reference_data }) => {
                let reference_data_path = Path::new(&reference_data);
                management::set_reference_data_cmd(reference_data_path, &args.addr).await?;
            }
            Some(ReferenceDataCommands::Restore) => {
                management::restore_default_reference_data_cmd(&args.addr).await?;
            }
            _ => {
                return Err(anyhow!("Unsupported command, use --help for information"));
            }
        },
        Commands::Attest {
            evidence,
            attest_addr,
        } => {
            let evidence_path = Path::new(&evidence);
            attestation::attestation_cmd(evidence_path, &attest_addr).await?;
        }
    }

    Ok(())
}
