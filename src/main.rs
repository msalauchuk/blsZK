use bls_zk_prover::{BLSPrivateInputs, BLSProofInputs, BLSProver, BLSPublicInputs, ProverResult};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::fs;
use std::num::NonZeroUsize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "bls-prover",
    about = "Groth16 demo CLI (BLS verification is not yet implemented)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Load existing artifacts and optionally export their verification key.
    Setup {
        #[arg(short, long, default_value = "./circuits")]
        circuit_path: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Generate a proof of the current demo relation.
    Prove {
        #[arg(short, long)]
        message_hash: String,
        #[arg(long)]
        public_key_x: String,
        #[arg(long)]
        public_key_y: String,
        #[arg(long)]
        signature_x: String,
        #[arg(long)]
        signature_y: String,
        #[arg(short, long, default_value = "./circuits")]
        circuit_path: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Verify a CLI artifact, or snarkjs proof JSON with --inputs-file.
    Verify {
        #[arg(short, long)]
        proof_file: PathBuf,
        #[arg(short, long)]
        inputs_file: Option<PathBuf>,
        #[arg(short, long, default_value = "./circuits")]
        circuit_path: String,
    },
    /// Measure repeated demo proofs using a satisfying fixture.
    Benchmark {
        #[arg(short, long, default_value = "10")]
        iterations: NonZeroUsize,
        #[arg(short, long, default_value = "./circuits")]
        circuit_path: String,
        #[arg(long, default_value = "circuits/test_input.json")]
        input_file: PathBuf,
    },
}

#[derive(Deserialize)]
struct ProofFile {
    proof: String,
    #[serde(rename = "publicInputs")]
    public_inputs: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CircuitInputs {
    message_hash: String,
    public_key_x: String,
    public_key_y: String,
    signature_x: String,
    signature_y: String,
}

impl From<CircuitInputs> for BLSProofInputs {
    fn from(input: CircuitInputs) -> Self {
        Self {
            public_inputs: BLSPublicInputs {
                message_hash: input.message_hash,
                public_key_x: input.public_key_x,
                public_key_y: input.public_key_y,
            },
            private_inputs: BLSPrivateInputs {
                signature_x: input.signature_x,
                signature_y: input.signature_y,
            },
        }
    }
}

fn load_prover(circuit_path: &str) -> ProverResult<BLSProver> {
    let mut prover = BLSProver::new(circuit_path);
    prover.setup()?;
    Ok(prover)
}

fn main() -> ProverResult<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Setup {
            circuit_path,
            output,
        } => {
            let prover = load_prover(&circuit_path)?;
            if let Some(path) = output {
                fs::write(path, prover.export_verifying_key()?)?;
            }
            println!("Loaded existing snarkjs artifacts (demo circuit).");
        }
        Commands::Prove {
            message_hash,
            public_key_x,
            public_key_y,
            signature_x,
            signature_y,
            circuit_path,
            output,
        } => {
            let prover = load_prover(&circuit_path)?;
            let inputs = BLSProofInputs::from(CircuitInputs {
                message_hash,
                public_key_x,
                public_key_y,
                signature_x,
                signature_y,
            });
            let (result, stats) = prover.generate_proof(inputs)?;
            let artifact = serde_json::json!({
                "proof": hex::encode(&result.proof),
                "publicInputs": result.public_inputs,
                "solidityCalldata": result.solidity_calldata,
                "stats": stats,
            });
            let json = serde_json::to_string_pretty(&artifact)?;
            if let Some(path) = output {
                fs::write(&path, json)?;
                println!("Proof saved to {}", path.display());
            } else {
                println!("{json}");
            }
        }
        Commands::Verify {
            proof_file,
            inputs_file,
            circuit_path,
        } => {
            let prover = load_prover(&circuit_path)?;
            let data = fs::read_to_string(proof_file)?;
            let (proof, public_inputs) = if let Some(path) = inputs_file {
                (
                    data,
                    serde_json::from_slice::<Vec<String>>(&fs::read(path)?)?,
                )
            } else {
                let artifact: ProofFile = serde_json::from_str(&data)?;
                (
                    String::from_utf8(hex::decode(artifact.proof)?)?,
                    artifact.public_inputs,
                )
            };
            if !prover.verify_proof(&proof, &public_inputs)? {
                return Err("Invalid proof".into());
            }
            println!("Proof verified (demo relation; not BLS verification).");
        }
        Commands::Benchmark {
            iterations,
            circuit_path,
            input_file,
        } => {
            let prover = load_prover(&circuit_path)?;
            let input: CircuitInputs = serde_json::from_slice(&fs::read(input_file)?)?;
            let input = BLSProofInputs::from(input);
            let mut proving_time = 0;
            let mut verification_time = 0;
            let mut proof_size = 0;
            for _ in 0..iterations.get() {
                let (_, stats) = prover.generate_proof(input.clone())?;
                proving_time += stats.proving_time_ms;
                verification_time += stats.verification_time_ms;
                proof_size += stats.proof_size_bytes;
            }
            println!("Demo relation benchmark (not BLS):");
            println!(
                "Average proving time: {} ms",
                proving_time / iterations.get() as u128
            );
            println!(
                "Average verification time: {} ms",
                verification_time / iterations.get() as u128
            );
            println!(
                "Average proof JSON size: {} bytes",
                proof_size / iterations.get()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_benchmark_iterations() {
        assert!(Cli::try_parse_from(["bls-prover", "benchmark", "--iterations", "0"]).is_err());
    }
}
