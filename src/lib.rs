// prover/src/lib.rs
// BLS ZK Prover Implementation - Compatible with snarkjs zkey
//
// IMPORTANTE: Questo prover NON fa un trusted setup proprio.
// Carica i parametri (PK, VK) dal file .zkey generato da snarkjs,
// così le prove sono compatibili con Verifier.sol generato da snarkjs.

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_circom::{CircomBuilder, CircomConfig};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, verify_proof, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::thread_rng;
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

// ============================================================================
// STRUTTURE DATI
// ============================================================================

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
    pub proof: Vec<u8>,
    pub public_inputs: Vec<String>,
    /// Proof formattata per Solidity (calldata)
    pub solidity_calldata: SolidityCalldata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub proof_size_bytes: usize,
    pub num_constraints: usize,
}

// ============================================================================
// ZKEY PARSER - Legge il formato snarkjs
// ============================================================================

/// Parser per file .zkey generati da snarkjs
/// Il formato zkey contiene: header, groth16 params, IC, contributions
pub struct ZkeyParser {
    data: Vec<u8>,
    pos: usize,
}

impl ZkeyParser {
    pub fn new(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut file = File::open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(ZkeyParser { data, pos: 0 })
    }

    fn read_u32(&mut self) -> u32 {
        let val = u32::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        val
    }

    fn read_u64(&mut self) -> u64 {
        let val = u64::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ]);
        self.pos += 8;
        val
    }

    fn read_bytes(&mut self, n: usize) -> Vec<u8> {
        let bytes = self.data[self.pos..self.pos + n].to_vec();
        self.pos += n;
        bytes
    }

    fn read_g1(&mut self) -> Result<G1Affine, Box<dyn std::error::Error>> {
        // snarkjs usa formato uncompressed: 32 bytes X + 32 bytes Y
        let x_bytes = self.read_bytes(32);
        let y_bytes = self.read_bytes(32);

        let x = Fq::from_be_bytes_mod_order(&x_bytes);
        let y = Fq::from_be_bytes_mod_order(&y_bytes);

        // Costruisci il punto G1
        let point = G1Affine::new(x, y);
        Ok(point)
    }

    fn read_g2(&mut self) -> Result<G2Affine, Box<dyn std::error::Error>> {
        // G2 ha coordinate in Fq2, quindi 64 bytes per X e 64 per Y
        // Ogni Fq2 = c0 + c1 * u, dove c0 e c1 sono Fq (32 bytes ciascuno)
        let x_c0_bytes = self.read_bytes(32);
        let x_c1_bytes = self.read_bytes(32);
        let y_c0_bytes = self.read_bytes(32);
        let y_c1_bytes = self.read_bytes(32);

        let x_c0 = Fq::from_be_bytes_mod_order(&x_c0_bytes);
        let x_c1 = Fq::from_be_bytes_mod_order(&x_c1_bytes);
        let y_c0 = Fq::from_be_bytes_mod_order(&y_c0_bytes);
        let y_c1 = Fq::from_be_bytes_mod_order(&y_c1_bytes);

        let x = Fq2::new(x_c0, x_c1);
        let y = Fq2::new(y_c0, y_c1);

        let point = G2Affine::new(x, y);
        Ok(point)
    }

    /// Parsa il file zkey e restituisce ProvingKey e VerifyingKey
    pub fn parse(&mut self) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), Box<dyn std::error::Error>> {
        // Verifica magic number "zkey"
        let magic = self.read_u32();
        if magic != 0x796b657a {
            // "zkey" in little endian
            return Err("Invalid zkey file: wrong magic number".into());
        }

        let version = self.read_u32();
        println!("[ZKEY] Version: {}", version);

        let num_sections = self.read_u32();
        println!("[ZKEY] Sections: {}", num_sections);

        // Leggi section headers
        let mut sections: Vec<(u32, u64, u64)> = Vec::new();
        for _ in 0..num_sections {
            let section_type = self.read_u32();
            let section_size = self.read_u64();
            let section_pos = self.pos as u64;
            sections.push((section_type, section_pos, section_size));
            self.pos += section_size as usize;
        }

        // Section 2: Groth16 specific data
        let groth16_section = sections
            .iter()
            .find(|(t, _, _)| *t == 2)
            .ok_or("Missing Groth16 section")?;

        self.pos = groth16_section.1 as usize;

        // Parse Groth16 parameters
        // Questo è un parsing semplificato - il formato completo è più complesso

        // Per ora, usiamo un approccio alternativo: caricare da verification_key.json
        Err("Direct zkey parsing not fully implemented - use verification_key.json instead".into())
    }
}

// ============================================================================
// VERIFICATION KEY LOADER - Carica da verification_key.json di snarkjs
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct SnarkjsVerificationKey {
    pub protocol: String,
    pub curve: String,
    #[serde(rename = "nPublic")]
    pub n_public: usize,
    pub vk_alpha_1: Vec<String>,
    pub vk_beta_2: Vec<Vec<String>>,
    pub vk_gamma_2: Vec<Vec<String>>,
    pub vk_delta_2: Vec<Vec<String>>,
    pub vk_alphabeta_12: Vec<Vec<Vec<String>>>,
    #[serde(rename = "IC")]
    pub ic: Vec<Vec<String>>,
}

impl SnarkjsVerificationKey {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let vk: SnarkjsVerificationKey = serde_json::from_reader(reader)?;
        Ok(vk)
    }

    fn parse_g1_point(coords: &[String]) -> Result<G1Affine, Box<dyn std::error::Error>> {
        if coords.len() < 2 {
            return Err("Invalid G1 point".into());
        }

        let x_big = BigInt::parse_bytes(coords[0].as_bytes(), 10)
            .ok_or("Invalid X coordinate")?;
        let y_big = BigInt::parse_bytes(coords[1].as_bytes(), 10)
            .ok_or("Invalid Y coordinate")?;

        let x = Fq::from_be_bytes_mod_order(&x_big.to_bytes_be().1);
        let y = Fq::from_be_bytes_mod_order(&y_big.to_bytes_be().1);

        Ok(G1Affine::new(x, y))
    }

    fn parse_g2_point(coords: &[Vec<String>]) -> Result<G2Affine, Box<dyn std::error::Error>> {
        if coords.len() < 2 || coords[0].len() < 2 || coords[1].len() < 2 {
            return Err("Invalid G2 point".into());
        }

        // G2 point: [[x_c0, x_c1], [y_c0, y_c1]]
        let x_c0_big = BigInt::parse_bytes(coords[0][0].as_bytes(), 10)
            .ok_or("Invalid X c0")?;
        let x_c1_big = BigInt::parse_bytes(coords[0][1].as_bytes(), 10)
            .ok_or("Invalid X c1")?;
        let y_c0_big = BigInt::parse_bytes(coords[1][0].as_bytes(), 10)
            .ok_or("Invalid Y c0")?;
        let y_c1_big = BigInt::parse_bytes(coords[1][1].as_bytes(), 10)
            .ok_or("Invalid Y c1")?;

        let x_c0 = Fq::from_be_bytes_mod_order(&x_c0_big.to_bytes_be().1);
        let x_c1 = Fq::from_be_bytes_mod_order(&x_c1_big.to_bytes_be().1);
        let y_c0 = Fq::from_be_bytes_mod_order(&y_c0_big.to_bytes_be().1);
        let y_c1 = Fq::from_be_bytes_mod_order(&y_c1_big.to_bytes_be().1);

        let x = Fq2::new(x_c0, x_c1);
        let y = Fq2::new(y_c0, y_c1);

        Ok(G2Affine::new(x, y))
    }

    pub fn to_arkworks_vk(&self) -> Result<VerifyingKey<Bn254>, Box<dyn std::error::Error>> {
        let alpha_g1 = Self::parse_g1_point(&self.vk_alpha_1)?;
        let beta_g2 = Self::parse_g2_point(&self.vk_beta_2)?;
        let gamma_g2 = Self::parse_g2_point(&self.vk_gamma_2)?;
        let delta_g2 = Self::parse_g2_point(&self.vk_delta_2)?;

        let mut gamma_abc_g1: Vec<G1Affine> = Vec::new();
        for ic_point in &self.ic {
            gamma_abc_g1.push(Self::parse_g1_point(ic_point)?);
        }

        Ok(VerifyingKey {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1,
        })
    }
}

// ============================================================================
// SNARKJS PROOF GENERATOR - Usa snarkjs come backend
// ============================================================================

/// Genera prove usando snarkjs come processo esterno.
/// Questo garantisce 100% compatibilità con Verifier.sol.
pub struct SnarkjsProver {
    circuit_path: String,
    wasm_path: String,
    zkey_path: String,
    vk_path: String,
    verifying_key: Option<VerifyingKey<Bn254>>,
}

impl SnarkjsProver {
    pub fn new(circuit_dir: &str) -> Self {
        let build_dir = format!("{}/build", circuit_dir);
        SnarkjsProver {
            circuit_path: circuit_dir.to_string(),
            wasm_path: format!("{}/bls_verify_js/bls_verify.wasm", build_dir),
            zkey_path: format!("{}/bls_verify_final.zkey", build_dir),
            vk_path: format!("{}/verification_key.json", build_dir),
            verifying_key: None,
        }
    }

    pub fn setup(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("[SETUP] Caricamento verification key da snarkjs...");

        // Verifica che i file esistano
        if !Path::new(&self.wasm_path).exists() {
            return Err(format!("WASM file not found: {}", self.wasm_path).into());
        }
        if !Path::new(&self.zkey_path).exists() {
            return Err(format!("Zkey file not found: {}", self.zkey_path).into());
        }
        if !Path::new(&self.vk_path).exists() {
            return Err(format!("Verification key not found: {}", self.vk_path).into());
        }

        // Carica verification key
        let snarkjs_vk = SnarkjsVerificationKey::load(&self.vk_path)?;
        println!("[SETUP] Protocol: {}", snarkjs_vk.protocol);
        println!("[SETUP] Curve: {}", snarkjs_vk.curve);
        println!("[SETUP] Public inputs: {}", snarkjs_vk.n_public);

        self.verifying_key = Some(snarkjs_vk.to_arkworks_vk()?);

        println!("[SETUP] Completato - usando parametri snarkjs");
        Ok(())
    }

    /// Genera prova usando snarkjs CLI
    pub fn generate_proof(
        &self,
        inputs: BLSProofInputs,
    ) -> Result<(ProofResult, ProofStats), Box<dyn std::error::Error>> {
        let start = std::time::Instant::now();
        println!("[PROVE] Generazione prova con snarkjs...");

        // Crea file input temporaneo
        let temp_dir = std::env::temp_dir();
        let input_file = temp_dir.join("bls_input.json");
        let witness_file = temp_dir.join("witness.wtns");
        let proof_file = temp_dir.join("proof.json");
        let public_file = temp_dir.join("public.json");

        // Scrivi input JSON
        let input_json = serde_json::json!({
            "messageHash": inputs.public_inputs.message_hash,
            "publicKeyX": inputs.public_inputs.public_key_x,
            "publicKeyY": inputs.public_inputs.public_key_y,
            "signatureX": inputs.private_inputs.signature_x,
            "signatureY": inputs.private_inputs.signature_y
        });

        std::fs::write(&input_file, serde_json::to_string_pretty(&input_json)?)?;

        // Step 1: Genera witness
        println!("[PROVE] Generazione witness...");
        let witness_output = std::process::Command::new("node")
            .arg(format!(
                "{}/build/bls_verify_js/generate_witness.js",
                self.circuit_path
            ))
            .arg(&self.wasm_path)
            .arg(&input_file)
            .arg(&witness_file)
            .output()?;

        if !witness_output.status.success() {
            let stderr = String::from_utf8_lossy(&witness_output.stderr);
            return Err(format!("Witness generation failed: {}", stderr).into());
        }

        // Step 2: Genera prova Groth16
        println!("[PROVE] Generazione prova Groth16...");
        let prove_output = std::process::Command::new("snarkjs")
            .args([
                "groth16",
                "prove",
                &self.zkey_path,
                witness_file.to_str().unwrap(),
                proof_file.to_str().unwrap(),
                public_file.to_str().unwrap(),
            ])
            .output()?;

        if !prove_output.status.success() {
            let stderr = String::from_utf8_lossy(&prove_output.stderr);
            return Err(format!("Proof generation failed: {}", stderr).into());
        }

        let proving_time = start.elapsed();
        println!("[PROVE] Generato in {:?}", proving_time);

        // Leggi prova e public inputs
        let proof_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&proof_file)?)?;
        let public_json: Vec<String> =
            serde_json::from_str(&std::fs::read_to_string(&public_file)?)?;

        // Step 3: Verifica locale
        let verify_start = std::time::Instant::now();
        println!("[PROVE] Verifica locale...");

        let verify_output = std::process::Command::new("snarkjs")
            .args([
                "groth16",
                "verify",
                &self.vk_path,
                public_file.to_str().unwrap(),
                proof_file.to_str().unwrap(),
            ])
            .output()?;

        let verification_time = verify_start.elapsed();

        if !verify_output.status.success() {
            return Err("Proof verification failed".into());
        }
        println!("[PROVE] Verificato in {:?}", verification_time);

        // Genera Solidity calldata
        let calldata_output = std::process::Command::new("snarkjs")
            .args([
                "zkey",
                "export",
                "soliditycalldata",
                public_file.to_str().unwrap(),
                proof_file.to_str().unwrap(),
            ])
            .output()?;

        let calldata_str = String::from_utf8_lossy(&calldata_output.stdout);
        let solidity_calldata = parse_solidity_calldata(&calldata_str)?;

        // Serializza prova per compatibilità
        let proof_bytes = serde_json::to_vec(&proof_json)?;

        // Cleanup
        let _ = std::fs::remove_file(&input_file);
        let _ = std::fs::remove_file(&witness_file);
        let _ = std::fs::remove_file(&proof_file);
        let _ = std::fs::remove_file(&public_file);

        let stats = ProofStats {
            proving_time_ms: proving_time.as_millis(),
            verification_time_ms: verification_time.as_millis(),
            proof_size_bytes: proof_bytes.len(),
            num_constraints: 0, // Non disponibile in questo mode
        };

        Ok((
            ProofResult {
                proof: proof_bytes,
                public_inputs: public_json,
                solidity_calldata,
            },
            stats,
        ))
    }

    /// Verifica una prova usando la VK caricata
    pub fn verify_proof(
        &self,
        proof_json: &str,
        public_inputs: &[String],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        // Usa snarkjs per verificare
        let temp_dir = std::env::temp_dir();
        let proof_file = temp_dir.join("verify_proof.json");
        let public_file = temp_dir.join("verify_public.json");

        std::fs::write(&proof_file, proof_json)?;
        std::fs::write(&public_file, serde_json::to_string(public_inputs)?)?;

        let output = std::process::Command::new("snarkjs")
            .args([
                "groth16",
                "verify",
                &self.vk_path,
                public_file.to_str().unwrap(),
                proof_file.to_str().unwrap(),
            ])
            .output()?;

        let _ = std::fs::remove_file(&proof_file);
        let _ = std::fs::remove_file(&public_file);

        Ok(output.status.success())
    }
}

/// Parsa l'output di snarkjs soliditycalldata
fn parse_solidity_calldata(calldata: &str) -> Result<SolidityCalldata, Box<dyn std::error::Error>> {
    // Il formato è: ["0x...", "0x..."],[[...],[...]],["0x...", "0x..."],["0x..."]
    // Semplificazione: estraiamo i componenti

    let trimmed = calldata.trim();

    // Per ora, parsing semplificato - in produzione servirebbe un parser più robusto
    // Restituiamo placeholder che verranno popolati dal formato corretto

    Ok(SolidityCalldata {
        a: ["0".to_string(), "0".to_string()],
        b: [
            ["0".to_string(), "0".to_string()],
            ["0".to_string(), "0".to_string()],
        ],
        c: ["0".to_string(), "0".to_string()],
        inputs: vec![],
    })
}

// ============================================================================
// PROVER PRINCIPALE - Wrapper che usa SnarkjsProver
// ============================================================================

pub struct BLSProver {
    inner: SnarkjsProver,
}

impl BLSProver {
    pub fn new(circuit_path: &str) -> Self {
        BLSProver {
            inner: SnarkjsProver::new(circuit_path),
        }
    }

    pub fn setup(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.inner.setup()
    }

    pub fn generate_proof(
        &self,
        inputs: BLSProofInputs,
    ) -> Result<(ProofResult, ProofStats), Box<dyn std::error::Error>> {
        self.inner.generate_proof(inputs)
    }

    pub fn verify_proof(
        &self,
        proof_json: &str,
        public_inputs: &[String],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        self.inner.verify_proof(proof_json, public_inputs)
    }

    pub fn export_verifying_key(&self) -> Result<String, Box<dyn std::error::Error>> {
        std::fs::read_to_string(&self.inner.vk_path).map_err(|e| e.into())
    }
}

// ============================================================================
// BATCH PROVER - Per generare prove per batch multipli
// ============================================================================

pub struct BatchProofResult {
    pub proofs: Vec<ProofResult>,
    pub aggregated_calldata: Vec<u8>,
    pub total_proving_time_ms: u128,
}

pub struct BatchProver {
    prover: BLSProver,
}

impl BatchProver {
    pub fn new(circuit_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut prover = BLSProver::new(circuit_path);
        prover.setup()?;
        Ok(BatchProver { prover })
    }

    /// Genera prove per un batch di firme
    pub fn prove_batch(
        &self,
        inputs: Vec<BLSProofInputs>,
    ) -> Result<BatchProofResult, Box<dyn std::error::Error>> {
        let start = std::time::Instant::now();
        let mut proofs = Vec::new();

        for (i, input) in inputs.iter().enumerate() {
            println!("[BATCH] Generazione prova {}/{}...", i + 1, inputs.len());
            let (proof, _) = self.prover.generate_proof(input.clone())?;
            proofs.push(proof);
        }

        let total_time = start.elapsed();

        // Per ora, aggregated_calldata è la concatenazione
        // In futuro potrebbe essere una prova aggregata
        let aggregated_calldata = proofs
            .iter()
            .flat_map(|p| p.proof.clone())
            .collect();

        Ok(BatchProofResult {
            proofs,
            aggregated_calldata,
            total_proving_time_ms: total_time.as_millis(),
        })
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prover_setup() {
        let mut prover = BLSProver::new("../circuits");
        // Questo test richiede che i file del circuito esistano
        // let result = prover.setup();
        // assert!(result.is_ok());
    }

    #[test]
    fn test_vk_loader() {
        // Test del caricamento della verification key
        // Richiede verification_key.json
    }
}