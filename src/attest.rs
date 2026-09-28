//! The bridge attestation (`ZMAP-v0.5.md` §12.3 "what stays", job 1).
//!
//! For a note whose lineage was broken by a pool boundary or a pre-§5.5
//! transfer, the issuer signs a statement that the note *held* is genuine, and
//! that note's `cmx` becomes the genesis of every later hop proof. This is a
//! trusted hop, permanent until cross-bundle proofs exist (§16).
//!
//! Message, all fields fixed-width or length-prefixed so no two inputs share an encoding:
//!
//! ```text
//! "zmap:attest:v1" ‖ cmx (32) ‖ I2BEOSP_16(len(asset_id)) ‖ asset_id ‖ I2BEOSP_32(unit) ‖ I2BEOSP_32(height)
//! ```
//!
//! Signed with ed25519 by the **attestation key**, which MUST be separate from
//! the issuance key (§12.3). The key file this tool reads is the 32-byte seed
//! in hex; keep it as the other keys are kept, never beside the wallet.

use anyhow::{anyhow, Context, Result};
use ed25519_zebra::{Signature, SigningKey, VerificationKey};
use serde::{Deserialize, Serialize};

use crate::oracle::{decode_hex_32, hex};
use crate::pin::decode_hex;

/// Domain separator.
pub const ATTEST_DOMAIN: &[u8] = b"zmap:attest:v1";

/// A signed attestation, as published to the holder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    pub cmx: String,
    pub asset_id: String,
    pub unit: u32,
    pub height: u32,
    /// The attestation public key, 32 bytes hex.
    pub attestation_key: String,
    /// 64 bytes hex.
    pub signature: String,
}

/// The exact bytes signed.
pub fn attest_message(cmx: &[u8; 32], asset_id: &[u8], unit: u32, height: u32) -> Vec<u8> {
    let mut m = Vec::with_capacity(ATTEST_DOMAIN.len() + 32 + 2 + asset_id.len() + 8);
    m.extend_from_slice(ATTEST_DOMAIN);
    m.extend_from_slice(cmx);
    m.extend_from_slice(&(asset_id.len() as u16).to_be_bytes());
    m.extend_from_slice(asset_id);
    m.extend_from_slice(&unit.to_be_bytes());
    m.extend_from_slice(&height.to_be_bytes());
    m
}

/// Sign an attestation with the attestation seed.
pub fn sign(seed: &[u8; 32], cmx: &[u8; 32], asset_id: &[u8], unit: u32, height: u32) -> Attestation {
    let sk = SigningKey::from(*seed);
    let vk = VerificationKey::from(&sk);
    let sig = sk.sign(&attest_message(cmx, asset_id, unit, height));
    let sig_bytes: [u8; 64] = sig.into();
    let vk_bytes: [u8; 32] = vk.into();
    Attestation {
        cmx: hex(cmx),
        asset_id: hex(asset_id),
        unit,
        height,
        attestation_key: hex(&vk_bytes),
        signature: hex(&sig_bytes),
    }
}

/// Why an attestation is not accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestError {
    Malformed(String),
    /// Signed by a key other than the one the verifier pinned.
    WrongKey,
    BadSignature,
}

impl std::fmt::Display for AttestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttestError::Malformed(s) => write!(f, "malformed attestation: {s}"),
            AttestError::WrongKey => write!(f, "attestation key is not the pinned key"),
            AttestError::BadSignature => write!(f, "attestation signature does not verify"),
        }
    }
}

impl std::error::Error for AttestError {}

/// Verify an attestation. `expected_key` is the attestation public key the
/// verifier pinned for this issuer; `None` checks only internal consistency,
/// which is never enough on its own.
pub fn verify(a: &Attestation, expected_key: Option<&[u8; 32]>) -> Result<[u8; 32], AttestError> {
    let mal = |e: anyhow::Error| AttestError::Malformed(e.to_string());
    let cmx = decode_hex_32(&a.cmx).map_err(mal)?;
    let asset_id = decode_hex(&a.asset_id).map_err(mal)?;
    let key = decode_hex_32(&a.attestation_key).map_err(mal)?;
    let sig: [u8; 64] = decode_hex(&a.signature)
        .map_err(mal)?
        .try_into()
        .map_err(|_| AttestError::Malformed("signature is not 64 bytes".into()))?;
    if let Some(k) = expected_key {
        if *k != key {
            return Err(AttestError::WrongKey);
        }
    }
    let vk = VerificationKey::try_from(key).map_err(|_| AttestError::Malformed("bad public key".into()))?;
    vk.verify(&Signature::from(sig), &attest_message(&cmx, &asset_id, a.unit, a.height))
        .map_err(|_| AttestError::BadSignature)?;
    Ok(cmx)
}

/// Read a 32-byte hex seed from a file.
pub fn read_seed(path: &std::path::Path) -> Result<[u8; 32]> {
    let s = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    decode_hex_32(s.trim()).map_err(|e| anyhow!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_and_every_field_is_bound() {
        let seed = [7u8; 32];
        let cmx = [1u8; 32];
        let a = sign(&seed, &cmx, b"asset", 3, 100);
        let key = decode_hex_32(&a.attestation_key).unwrap();
        assert_eq!(verify(&a, Some(&key)), Ok(cmx));
        assert_eq!(verify(&a, None), Ok(cmx));

        let mut t = a.clone();
        t.unit = 4;
        assert_eq!(verify(&t, Some(&key)), Err(AttestError::BadSignature));
        let mut t = a.clone();
        t.height = 101;
        assert_eq!(verify(&t, Some(&key)), Err(AttestError::BadSignature));
        let mut t = a.clone();
        t.asset_id = hex(b"asse");
        assert_eq!(verify(&t, Some(&key)), Err(AttestError::BadSignature));
        let mut t = a.clone();
        t.cmx = hex(&[2u8; 32]);
        assert_eq!(verify(&t, Some(&key)), Err(AttestError::BadSignature));
        assert_eq!(verify(&a, Some(&[9u8; 32])), Err(AttestError::WrongKey));
    }

    #[test]
    fn message_has_no_ambiguous_boundaries() {
        // asset_id "ab" + unit 0x00000063 must not collide with asset_id "ab\0\0\0c" etc.
        let m1 = attest_message(&[0; 32], b"ab", 0x63, 0);
        let m2 = attest_message(&[0; 32], b"ab\0\0\0c", 0, 0);
        assert_ne!(m1, m2);
    }
}
