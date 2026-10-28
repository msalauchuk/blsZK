// prover/src/main.rs
// CLI interface for BLS ZK Prover

use bls_zk_prover::{BLSProver, BLSProofInputs, BLSPublicInputs, BLSPrivateInputs};
use clap::{Parser, Subcommand};
use std::fs;

#[derive(Parser)]
#[command(name = "bls-prover")]
#[command(about = "BLS Signature ZK Prover CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Esegue il trusted setup del circuito
    Setup {
        #[arg(short, long, default_value = "../circuits")]
        circuit_path: String,

        #[arg(short, long)]
        output: Option<String>,
    },

    /// Genera una prova ZK
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

        #[arg(short, long, default_value = "../circuits")]
        circuit_path: String,

        #[arg(short, long)]
        output: Option<String>,
    },

    /// Verifica una prova
    Verify {
        #[arg(short, long)]
        proof_file: String,

        #[arg(short, long)]
        inputs_file: String,

        #[arg(short, long, default_value = "../circuits")]
        circuit_path: String,
    },

    /// Benchmark di performance
    Benchmark {
        #[arg(short, long, default_value = "10")]
        iterations: usize,

        #[arg(short, long, default_value = "../circuits")]
        circuit_path: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Setup { circuit_path, output } => {
            println!("=== BLS ZK Prover - Trusted Setup ===\n");

            let mut prover = BLSProver::new(&circuit_path);
            prover.setup()?;

            if let Some(output_path) = output {
                let vk = prover.export_verifying_key()?;
                fs::write(&output_path, vk)?;
                println!("\nVerifying key salvata in: {}", output_path);
            }

            println!("\nSetup completato con successo");
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
            println!("=== BLS ZK Prover - Generazione Prova ===\n");

            let mut prover = BLSProver::new(&circuit_path);
            prover.setup()?;

            let inputs = BLSProofInputs {
                public_inputs: BLSPublicInputs {
                    message_hash: message_hash.clone(),
                    public_key_x: public_key_x.clone(),
                    public_key_y: public_key_y.clone(),
                },
                private_inputs: BLSPrivateInputs {
                    signature_x,
                    signature_y,
                },
            };

            println!("Input pubblici:");
            println!("  Message hash: {}", message_hash);
            println!("  Public key X: {}", public_key_x);
            println!("  Public key Y: {}", public_key_y);
            println!();

            let (result, stats) = prover.generate_proof(inputs)?;

            println!("\n=== Statistiche ===");
            println!("Proving time: {} ms", stats.proving_time_ms);
            println!("Verification time: {} ms", stats.verification_time_ms);
            println!("Proof size: {} bytes", stats.proof_size_bytes);
            println!("Constraints: {}", stats.num_constraints);

            if let Some(output_path) = output {
                let output_data = serde_json::json!({
                    "proof": hex::encode(&result.proof),
                    "publicInputs": result.public_inputs,
                    "stats": stats,
                });

                fs::write(&output_path, serde_json::to_string_pretty(&output_data)?)?;
                println!("\nProva salvata in: {}", output_path);
            } else {
                println!("\nProof (hex): {}", hex::encode(&result.proof));
            }
        }

        Commands::Verify {
            proof_file,
            inputs_file,
            circuit_path,
        } => {
            println!("=== BLS ZK Prover - Verifica Prova ===\n");

            let mut prover = BLSProver::new(&circuit_path);
            prover.setup()?;

            let proof_data = fs::read_to_string(proof_file)?;
            let proof_json: serde_json::Value = serde_json::from_str(&proof_data)?;

            let proof_hex = proof_json["proof"].as_str().ok_or("Missing proof")?;
            let proof_bytes = hex::decode(proof_hex)?;

            let public_inputs: Vec<String> = proof_json["publicInputs"]
                .as_array()
                .ok_or("Missing publicInputs")?
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();

            let is_valid = prover.verify_proof(&proof_bytes, &public_inputs)?;

            if is_valid {
                println!("PROVA VALIDA");
            } else {
                println!("PROVA NON VALIDA");
            }
        }

        Commands::Benchmark {
            iterations,
            circuit_path,
        } => {
            println!("=== BLS ZK Prover - Benchmark ===\n");
            println!("Iterazioni: {}\n", iterations);

            let mut prover = BLSProver::new(&circuit_path);
            prover.setup()?;

            let mut total_proving_time = 0u128;
            let mut total_verification_time = 0u128;
            let mut total_proof_size = 0usize;

            for i in 0..iterations {
                let inputs = BLSProofInputs {
                    public_inputs: BLSPublicInputs {
                        message_hash: format!("{}", i * 12345),
                        public_key_x: format!("{}", i * 67890),
                        public_key_y: format!("{}", i * 11111),
                    },
                    private_inputs: BLSPrivateInputs {
                        signature_x: format!("{}", i * 22222),
                        signature_y: format!("{}", i * 33333),
                    },
                };

                let (result, stats) = prover.generate_proof(inputs)?;

                total_proving_time += stats.proving_time_ms;
                total_verification_time += stats.verification_time_ms;
                total_proof_size += stats.proof_size_bytes;

                println!("Iterazione {}: {} ms (prove), {} ms (verify)",
                         i + 1, stats.proving_time_ms, stats.verification_time_ms);
            }

            println!("\n=== Risultati ===");
            println!("Media proving time: {} ms", total_proving_time / iterations as u128);
            println!("Media verification time: {} ms", total_verification_time / iterations as u128);
            println!("Media proof size: {} bytes", total_proof_size / iterations);
        }
    }

    Ok(())
}
