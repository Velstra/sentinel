//! # Velstra Sentinel
//!
//! A standalone, **immutable** firewall/router appliance OS built on the Velstra
//! eBPF/XDP data plane. Velstra is the engine; Sentinel is the product on top.
//!
//! Unlike a mutable, log-in-and-tweak box (VyOS), a Sentinel appliance is
//! image-based and **declarative**: the whole box is described by one config
//! document that the system reconciles to atomically. This CLI is how you author
//! and apply that document — and, via [`velstra_proto`] (from crates.io), talk to
//! a running Velstra controller.

mod compile;
mod config;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use velstra_proto::{ListPortsRequest, velstra_orchestrator_client::VelstraOrchestratorClient};

use crate::config::Appliance;

/// A config serialization format.
#[derive(Copy, Clone, Debug, ValueEnum)]
enum Format {
    Toml,
    Json,
}

#[derive(Parser)]
#[command(name = "sentinel", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Author the declarative appliance config.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Compile the appliance config into a Velstra agent config (to stdout).
    Compile {
        /// Path to the appliance config (TOML or JSON).
        file: PathBuf,
    },
    /// List the ports a Velstra controller currently knows about.
    Ports {
        /// The controller's orchestrator/admin endpoint.
        #[arg(long, default_value = "http://127.0.0.1:50052")]
        controller: String,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Print a commented starter config to stdout.
    Init,
    /// Parse and validate a config file (exit non-zero if invalid).
    Check {
        /// Path to the appliance config (TOML).
        file: PathBuf,
    },
    /// Parse a config file and print a normalized summary.
    Show {
        /// Path to the appliance config (TOML or JSON).
        file: PathBuf,
    },
    /// Convert a config between TOML and JSON (format in is by extension).
    Convert {
        /// Path to the appliance config (`.json` → JSON, else TOML).
        file: PathBuf,
        /// Output format.
        #[arg(long, value_enum)]
        to: Format,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Config { action } => config_cmd(action),
        Command::Compile { file } => {
            let appliance = Appliance::load(&file)?;
            print!("{}", compile::compile(&appliance).to_toml()?);
            Ok(())
        }
        Command::Ports { controller } => ports(&controller).await,
    }
}

fn config_cmd(action: ConfigAction) -> Result<()> {
    match action {
        ConfigAction::Init => {
            print!("{}", config::EXAMPLE);
            Ok(())
        }
        ConfigAction::Check { file } => {
            Appliance::load(&file)?;
            println!("{} is valid", file.display());
            Ok(())
        }
        ConfigAction::Show { file } => {
            print!("{}", Appliance::load(&file)?.summary());
            Ok(())
        }
        ConfigAction::Convert { file, to } => {
            let appliance = Appliance::load(&file)?;
            let out = match to {
                Format::Toml => appliance.to_toml()?,
                Format::Json => appliance.to_json()?,
            };
            print!("{out}");
            Ok(())
        }
    }
}

/// Connect to a Velstra controller and print its ports — a working first use of
/// the shared `velstra-proto` wire types.
async fn ports(endpoint: &str) -> Result<()> {
    let mut client = VelstraOrchestratorClient::connect(endpoint.to_string())
        .await
        .with_context(|| format!("connecting to controller {endpoint}"))?;
    let resp = client
        .list_ports(ListPortsRequest {})
        .await
        .context("ListPorts RPC")?
        .into_inner();

    println!("{:<22} {:>6}  {:<15} host", "id", "vni", "ip");
    for p in resp.ports {
        println!("{:<22} {:>6}  {:<15} {}", p.id, p.vni, p.ip, p.host);
    }
    Ok(())
}
