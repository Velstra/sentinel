//! Isolated test helper using the exact Aya revision and attachment API of Fabric.
use std::{env, error::Error, io};

use aya::programs::{SchedClassifier, TcAttachType, links::FdLink};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        return Err(io::Error::other(
            "usage: fragment-tcx-attach PINNED_PROGRAM INTERFACE ingress|egress PINNED_LINK",
        )
        .into());
    }
    let kind = match args[3].as_str() {
        "ingress" => TcAttachType::Ingress,
        "egress" => TcAttachType::Egress,
        _ => return Err(io::Error::other("invalid attach direction").into()),
    };
    let mut program = SchedClassifier::from_pin(&args[1])?;
    // Deliberately the production default API, not explicit legacy netlink.
    let id = program.attach(&args[2], kind)?;
    let link: FdLink = program.take_link(id)?.try_into()?;
    link.pin(&args[4])?;
    println!(
        "AYA_REV=6f6859fbc0857b792f78fe4a128c6808267cbfcf API=SchedClassifier::attach direction={}",
        args[3]
    );
    Ok(())
}
