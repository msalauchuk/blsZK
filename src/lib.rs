//! Rust orchestration for the snarkjs Groth16 demo pipeline.
//!
//! The current circuit proves a Poseidon relation, not BLS signature validity.
//! Proving and verification both use snarkjs and its generated keys.

use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Instant;

pub mod bls;

pub type ProverResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BLSPublicInputs {
    pub message_hash: String,
    pub public_key_x: String,
    pub public_key_y: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BLSPrivateInputs {
    pub signature_x: String,
    pub signature_y: String,
}

#[derive(Debug, Clone)]
pub struct BLSProofInputs {
    pub public_inputs: BLSPublicInputs,
    pub private_inputs: BLSPrivateInputs,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofResult {
    /// UTF-8 snarkjs proof JSON, not ABI-encoded curve coordinates.
    pub proof: Vec<u8>,
    pub public_inputs: Vec<String>,
    pub solidity_calldata: SolidityCalldata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolidityCalldata {
    pub a: [String; 2],
    pub b: [[String; 2]; 2],
    pub c: [String; 2],
    pub inputs: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofStats {
    pub proving_time_ms: u128,
    pub verification_time_ms: u128,
    /// Serialized proof JSON size, not Solidity calldata size.
    pub proof_size_bytes: usize,
    pub num_constraints: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct VerificationKeyHeader {
    protocol: String,
    curve: String,
    #[serde(rename = "nPublic")]
    n_public: usize,
}

pub struct SnarkjsProver {
    build_dir: PathBuf,
    snarkjs_cli: PathBuf,
    verifying_key: Option<VerificationKeyHeader>,
}

impl SnarkjsProver {
    pub fn new(circuit_dir: &str) -> Self {
        let circuit_dir = Path::new(circuit_dir);
        Self {
            build_dir: circuit_dir.join("build"),
            snarkjs_cli: circuit_dir
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join("node_modules/snarkjs/build/cli.cjs"),
            verifying_key: None,
        }
    }

    fn snarkjs(&self) -> Command {
        if self.snarkjs_cli.is_file() {
            let mut command = Command::new("node");
            command.arg(&self.snarkjs_cli);
            command
        } else {
            Command::new("snarkjs")
        }
    }

    /// Load existing circuit artifacts. This does not run a trusted setup.
    pub fn setup(&mut self) -> ProverResult<()> {
        self.verifying_key = None;
        for name in [
            "bls_verify_js/bls_verify.wasm",
            "bls_verify_js/generate_witness.js",
            "bls_verify_final.zkey",
            "verification_key.json",
        ] {
            let path = self.build_dir.join(name);
            if !path.is_file() {
                return Err(format!(
                    "Missing artifact: {}. Run npm run circuit:compile first.",
                    path.display()
                )
                .into());
            }
        }
        let key: VerificationKeyHeader =
            serde_json::from_slice(&fs::read(self.build_dir.join("verification_key.json"))?)?;
        if key.protocol != "groth16" || key.curve != "bn128" {
            return Err("Expected a snarkjs Groth16 verification key on BN254 (bn128)".into());
        }
        self.verifying_key = Some(key);
        Ok(())
    }

    fn key(&self) -> ProverResult<&VerificationKeyHeader> {
        self.verifying_key
            .as_ref()
            .ok_or_else(|| "Call setup() before proving or verifying".into())
    }

    pub fn generate_proof(
        &self,
        inputs: BLSProofInputs,
    ) -> ProverResult<(ProofResult, ProofStats)> {
        self.key()?;
        // Each operation gets a private directory, including concurrent processes.
        let work = tempfile::tempdir()?;
        let input_file = work.path().join("input.json");
        let witness_file = work.path().join("witness.wtns");
        let proof_file = work.path().join("proof.json");
        let public_file = work.path().join("public.json");
        let input_json = serde_json::json!({
            "messageHash": inputs.public_inputs.message_hash,
            "publicKeyX": inputs.public_inputs.public_key_x,
            "publicKeyY": inputs.public_inputs.public_key_y,
            "signatureX": inputs.private_inputs.signature_x,
            "signatureY": inputs.private_inputs.signature_y,
        });
        fs::write(&input_file, serde_json::to_vec(&input_json)?)?;

        let start = Instant::now();
        checked_output(
            Command::new("node")
                .arg(self.build_dir.join("bls_verify_js/generate_witness.js"))
                .arg(self.build_dir.join("bls_verify_js/bls_verify.wasm"))
                .arg(&input_file)
                .arg(&witness_file),
        )?;
        checked_output(
            self.snarkjs()
                .args(["groth16", "prove"])
                .arg(self.build_dir.join("bls_verify_final.zkey"))
                .arg(&witness_file)
                .arg(&proof_file)
                .arg(&public_file),
        )?;
        let proving_time_ms = start.elapsed().as_millis();
        let proof = fs::read(&proof_file)?;
        let public_inputs: Vec<String> = serde_json::from_slice(&fs::read(&public_file)?)?;

        let start = Instant::now();
        if !self.verify_proof(std::str::from_utf8(&proof)?, &public_inputs)? {
            return Err("Generated proof failed verification".into());
        }
        let verification_time_ms = start.elapsed().as_millis();
        let calldata = checked_output(
            self.snarkjs()
                .args(["zkey", "export", "soliditycalldata"])
                .arg(&public_file)
                .arg(&proof_file),
        )?;
        let solidity_calldata = parse_solidity_calldata(std::str::from_utf8(&calldata.stdout)?)?;
        let stats = ProofStats {
            proving_time_ms,
            verification_time_ms,
            proof_size_bytes: proof.len(),
            num_constraints: None,
        };
        Ok((
            ProofResult {
                proof,
                public_inputs,
                solidity_calldata,
            },
            stats,
        ))
    }

    /// Verify snarkjs proof JSON with all public signals (including outputs).
    pub fn verify_proof(&self, proof_json: &str, public_inputs: &[String]) -> ProverResult<bool> {
        if public_inputs.len() != self.key()?.n_public {
            return Ok(false);
        }
        // Reject invalid JSON locally rather than passing malformed data to a tool.
        serde_json::from_str::<serde_json::Value>(proof_json)?;
        let work = tempfile::tempdir()?;
        let proof_file = work.path().join("proof.json");
        let public_file = work.path().join("public.json");
        fs::write(&proof_file, proof_json)?;
        fs::write(&public_file, serde_json::to_vec(public_inputs)?)?;
        let output = self
            .snarkjs()
            .args(["groth16", "verify"])
            .arg(self.build_dir.join("verification_key.json"))
            .arg(&public_file)
            .arg(&proof_file)
            .output()?;
        match output.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(command_error(&output).into()),
        }
    }

    pub fn export_verifying_key(&self) -> ProverResult<String> {
        self.key()?;
        Ok(fs::read_to_string(
            self.build_dir.join("verification_key.json"),
        )?)
    }
}

fn command_error(output: &Output) -> String {
    format!(
        "Prover command failed ({}): {}{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    )
}

fn checked_output(command: &mut Command) -> ProverResult<Output> {
    let output = command.output()?;
    if !output.status.success() {
        return Err(command_error(&output).into());
    }
    Ok(output)
}

fn parse_solidity_calldata(calldata: &str) -> ProverResult<SolidityCalldata> {
    type CalldataTuple = ([String; 2], [[String; 2]; 2], [String; 2], Vec<String>);
    // snarkjs emits four comma-separated JSON values without an outer array.
    let (a, b, c, inputs): CalldataTuple = serde_json::from_str(&format!("[{}]", calldata.trim()))?;
    Ok(SolidityCalldata { a, b, c, inputs })
}

pub type BLSProver = SnarkjsProver;

pub struct BatchProofResult {
    pub proofs: Vec<ProofResult>,
    /// Concatenated proof JSON bytes. This is NOT an aggregated Groth16 proof.
    pub aggregated_calldata: Vec<u8>,
    pub total_proving_time_ms: u128,
}

pub struct BatchProver {
    prover: BLSProver,
}

impl BatchProver {
    pub fn new(circuit_path: &str) -> ProverResult<Self> {
        let mut prover = BLSProver::new(circuit_path);
        prover.setup()?;
        Ok(Self { prover })
    }

    /// Generate independent proofs sequentially; no cryptographic aggregation.
    pub fn prove_batch(&self, inputs: Vec<BLSProofInputs>) -> ProverResult<BatchProofResult> {
        let start = Instant::now();
        let proofs: Vec<ProofResult> = inputs
            .into_iter()
            .map(|input| self.prover.generate_proof(input).map(|result| result.0))
            .collect::<ProverResult<_>>()?;
        let aggregated_calldata = proofs
            .iter()
            .flat_map(|proof| proof.proof.clone())
            .collect();
        Ok(BatchProofResult {
            proofs,
            aggregated_calldata,
            total_proving_time_ms: start.elapsed().as_millis(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_snarkjs_calldata_without_reordering_g2_coordinates() {
        let calldata = r#"["0x01","0x02"],[["0x03","0x04"],["0x05","0x06"]],["0x07","0x08"],["0x01","0x09","0x0a","0x0b"]"#;
        let parsed = parse_solidity_calldata(calldata).unwrap();
        assert_eq!(parsed.a, ["0x01", "0x02"]);
        assert_eq!(parsed.b, [["0x03", "0x04"], ["0x05", "0x06"]]);
        assert_eq!(parsed.c, ["0x07", "0x08"]);
        assert_eq!(parsed.inputs, ["0x01", "0x09", "0x0a", "0x0b"]);
    }

    #[test]
    fn rejects_truncated_calldata() {
        assert!(parse_solidity_calldata(r#"["1","2"],[],["7","8"],[]"#).is_err());
    }

    #[test]
    fn reports_missing_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let mut prover = BLSProver::new(dir.path().to_str().unwrap());
        let error = prover.setup().unwrap_err().to_string();
        assert!(error.contains("Missing artifact:"));
        assert!(error.contains("npm run circuit:compile"));
    }

    #[test]
    fn requires_setup_before_verification() {
        let prover = BLSProver::new("circuits");
        assert!(prover.verify_proof("{}", &[]).is_err());
    }
}
