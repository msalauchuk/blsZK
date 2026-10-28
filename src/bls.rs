//! Native reference for the BLS12-381 Basic scheme (minimal public keys).
//!
//! This performs real signature verification. It does not generate a ZK proof.

use crate::ProverResult;
use blst::{
    min_pk::{PublicKey, SecretKey, Signature},
    BLST_ERROR,
};
use serde::{Deserialize, Serialize};

/// The ciphersuite/DST is fixed, rather than selected by untrusted input.
pub const CIPHERSUITE: &str = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BlsStatement {
    pub ciphersuite: String,
    /// Arbitrary message bytes encoded as hex, with an optional 0x prefix.
    pub message: String,
    /// Compressed G1 point: exactly 48 bytes.
    pub public_key: String,
    /// Compressed G2 point: exactly 96 bytes.
    pub signature: String,
}

fn decode(value: &str) -> ProverResult<Vec<u8>> {
    Ok(hex::decode(value.strip_prefix("0x").unwrap_or(value))?)
}

impl BlsStatement {
    /// Validate canonical encodings, nonidentity points and subgroup membership,
    /// then check the pairing equation with hash-to-curve inside blst.
    pub fn verify(&self) -> ProverResult<bool> {
        if self.ciphersuite != CIPHERSUITE {
            return Err("Unsupported BLS ciphersuite".into());
        }
        let message = decode(&self.message)?;
        let public_key = decode(&self.public_key)?;
        let signature = decode(&self.signature)?;
        if public_key.len() != 48 || signature.len() != 96 {
            return Err(
                "Expected a 48-byte compressed public key and a 96-byte compressed signature"
                    .into(),
            );
        }
        let public_key = match PublicKey::key_validate(&public_key) {
            Ok(key) => key,
            Err(_) => return Ok(false),
        };
        let signature = match Signature::sig_validate(&signature, true) {
            Ok(signature) => signature,
            Err(_) => return Ok(false),
        };
        Ok(signature.verify(
            true,
            &message,
            CIPHERSUITE.as_bytes(),
            &[],
            &public_key,
            true,
        ) == BLST_ERROR::BLST_SUCCESS)
    }
}

/// A deterministic PUBLIC test fixture. Never use its known key for funds.
/// The fixed IKM is solely for reproducible cross-implementation tests.
pub fn test_fixture(message: &[u8]) -> BlsStatement {
    let key = SecretKey::key_gen(&[0x42; 32], &[]).expect("32-byte test IKM is valid");
    BlsStatement {
        ciphersuite: CIPHERSUITE.to_string(),
        message: format!("0x{}", hex::encode(message)),
        public_key: format!("0x{}", hex::encode(key.sk_to_pk().compress())),
        signature: format!(
            "0x{}",
            hex::encode(key.sign(message, CIPHERSUITE.as_bytes(), &[]).compress())
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_empty_and_binary_messages() {
        for message in [b"".as_slice(), b"abc", &[0, 255, 0, 128]] {
            assert!(test_fixture(message).verify().unwrap());
        }
    }

    #[test]
    fn rejects_changed_message_signature_and_key() {
        let original = test_fixture(b"blsZK reference");
        let mut changed = original.clone();
        changed.message = "0x00".into();
        assert!(!changed.verify().unwrap());
        let other = SecretKey::key_gen(&[0x43; 32], &[]).unwrap();
        changed = original.clone();
        changed.public_key = hex::encode(other.sk_to_pk().compress());
        assert!(!changed.verify().unwrap());
        changed = original;
        changed.signature = hex::encode(
            other
                .sign(b"blsZK reference", CIPHERSUITE.as_bytes(), &[])
                .compress(),
        );
        assert!(!changed.verify().unwrap());
    }

    #[test]
    fn rejects_infinity_and_non_subgroup_public_keys() {
        let mut statement = test_fixture(b"abc");
        let mut infinity = vec![0; 48];
        infinity[0] = 0xc0;
        statement.public_key = hex::encode(infinity);
        assert!(!statement.verify().unwrap());
        // (0,2) is on y^2 = x^3 + 4 but has order 3, outside prime-order G1.
        let mut torsion = vec![0; 48];
        torsion[0] = 0x80;
        statement.public_key = hex::encode(torsion);
        assert!(!statement.verify().unwrap());

        statement = test_fixture(b"abc");
        let mut infinity = vec![0; 96];
        infinity[0] = 0xc0;
        statement.signature = hex::encode(infinity);
        assert!(!statement.verify().unwrap());
    }

    #[test]
    fn rejects_noncanonical_coordinates_and_wrong_encoding_lengths() {
        let mut statement = test_fixture(b"abc");
        let mut noncanonical = [0xff; 48];
        noncanonical[0] = 0x9f;
        statement.public_key = hex::encode(noncanonical);
        assert!(!statement.verify().unwrap());
        statement = test_fixture(b"abc");
        statement.public_key.push_str("00");
        assert!(statement.verify().is_err());
        statement = test_fixture(b"abc");
        statement.signature = "0x123".into();
        assert!(statement.verify().is_err());
    }

    #[test]
    fn rejects_wrong_domain_and_schema_fields() {
        let mut statement = test_fixture(b"abc");
        statement.ciphersuite = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_".into();
        assert!(statement.verify().is_err());
        let mut json = serde_json::to_value(test_fixture(b"abc")).unwrap();
        json["isValid"] = serde_json::json!(true);
        assert!(serde_json::from_value::<BlsStatement>(json).is_err());
    }
}
