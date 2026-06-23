//! # Velstra Sentinel
//!
//! A standalone firewall/router **appliance** built on the Velstra eBPF/XDP data
//! plane — the VyOS/pfSense-shaped product where Velstra is the engine. Sentinel
//! adds the appliance layer: turnkey config management, a control/admin surface,
//! and (eventually) an OS image and HA.
//!
//! This skeleton is the first slice: a CLI that speaks the Velstra control-plane
//! protocol ([`velstra_proto`], from crates.io) to a Velstra controller. It
//! proves the shared-protocol wiring across repos; real appliance features build
//! out from here.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use velstra_proto::{ListPortsRequest, velstra_orchestrator_client::VelstraOrchestratorClient};

#[derive(Parser)]
#[command(name = "sentinel", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List the ports a Velstra controller currently knows about.
    Ports {
        /// The controller's orchestrator/admin endpoint.
        #[arg(long, default_value = "http://127.0.0.1:50052")]
        controller: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Ports { controller } => ports(&controller).await,
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
