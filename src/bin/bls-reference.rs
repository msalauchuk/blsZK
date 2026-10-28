use bls_zk_prover::{
    bls::{self, BlsStatement},
    ProverResult,
};
use clap::{Parser, Subcommand};
use std::{fs, path::PathBuf};

#[derive(Parser)]
#[command(about = "Real BLS12-381 reference verification; no ZK proof is generated")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a reproducible fixture signed with a publicly known TEST key.
    Fixture {
        #[arg(long, default_value = "blsZK BLS12-381 reference")]
        message: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Verify a compressed-key/signature JSON statement using the fixed suite.
    Verify {
        #[arg(short, long)]
        input: PathBuf,
    },
}

fn main() -> ProverResult<()> {
    match Cli::parse().command {
        Command::Fixture { message, output } => {
            let statement = bls::test_fixture(message.as_bytes());
            let json = serde_json::to_string_pretty(&statement)? + "\n";
            if let Some(output) = output {
                fs::write(output, json)?;
            } else {
                print!("{json}");
            }
        }
        Command::Verify { input } => {
            let statement: BlsStatement = serde_json::from_slice(&fs::read(input)?)?;
            if !statement.verify()? {
                return Err("Invalid BLS signature".into());
            }
            println!("BLS12-381 signature verified (native reference, no ZK proof).");
        }
    }
    Ok(())
}
