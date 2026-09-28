//! The on-chain manifest pin (`ZMAP-v0.5.md` §7.3).
//!
//! Before serving generation `g`, the issuer publishes, from the issuance
//! address, a transaction with one shielded output to itself whose memo is
//!
//! ```text
//! "zmap:manifest:v1" ‖ I2BEOSP_32(g) ‖ SHA-256(manifest_bytes)
//! ```
//!
//! then NUL padding to 512. That is 16 + 4 + 32 = **52** bytes; the spec says 53
//! (erratum recorded 2026-09-25). `manifest_bytes` are the served bytes exactly,
//! the same bytes the `.sig` covers (§7.3.1).
//!
//! The pin sidecar `issuance_manifest.pin.json` is `{ generation, txid, action_index, ock }`.
//! It needs no signature: the OCK is self-authenticating, the recovered memo must
//! hash-match the bytes the verifier fetched, and the output must belong to the
//! issuance address.
//!
//! What this module does NOT do: build or send the pin transaction. That needs
//! the issuance wallet (the FROST vault); the tool prints the memo to put in it.

use anyhow::{anyhow, bail, Context, Result};
use orchard::note_encryption::IronwoodDomain;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::process::Command;
use zcash_note_encryption::{try_output_recovery_with_ock, OutgoingCipherKey};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};

use crate::oracle::{decode_hex_32, hex, ZebradOracle};

/// The memo prefix.
pub const PIN_PREFIX: &[u8; 16] = b"zmap:manifest:v1";
/// Bytes of meaning in the memo before NUL padding.
pub const PIN_MEMO_LEN: usize = 16 + 4 + 32;
/// A shielded memo is exactly this long.
pub const MEMO_SIZE: usize = 512;

/// The pin sidecar, served beside the manifest and its signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinSidecar {
    pub generation: u32,
    /// Display-order hex.
    pub txid: String,
    pub action_index: u32,
    /// 32 bytes hex: the outgoing cipher key of that output.
    pub ock: String,
}

/// `SHA-256` of the manifest bytes as served.
pub fn manifest_hash(manifest_bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(manifest_bytes));
    out
}

/// The 512-byte memo that pins `manifest_bytes` as generation `generation`.
pub fn pin_memo(generation: u32, manifest_bytes: &[u8]) -> [u8; MEMO_SIZE] {
    let mut m = [0u8; MEMO_SIZE];
    m[..16].copy_from_slice(PIN_PREFIX);
    m[16..20].copy_from_slice(&generation.to_be_bytes());
    m[20..52].copy_from_slice(&manifest_hash(manifest_bytes));
    m
}

/// Parse a memo as a pin. `None` if it is not one: wrong prefix, or anything
/// but NUL after the 52 bytes.
pub fn parse_pin_memo(memo: &[u8; MEMO_SIZE]) -> Option<(u32, [u8; 32])> {
    if &memo[..16] != PIN_PREFIX {
        return None;
    }
    if memo[PIN_MEMO_LEN..].iter().any(|&b| b != 0) {
        return None;
    }
    let generation = u32::from_be_bytes(memo[16..20].try_into().unwrap());
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&memo[20..52]);
    Some((generation, hash))
}

/// Why a pin did not verify (`ZMAP-v0.5.md` §7.3.2, §9 check 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PinFailure {
    /// The sidecar's generation is not the manifest's.
    SidecarGeneration { sidecar: u32, manifest: u32 },
    /// The node does not know the pin transaction as mined.
    TxNotFound,
    /// The transaction has no Ironwood Action at that index.
    NoSuchAction,
    /// The OCK does not recover the output. A forged sidecar, or the wrong output.
    OckDoesNotRecover,
    /// The recovered memo is not a pin memo.
    NotAPinMemo,
    /// The memo pins a different generation than the manifest claims.
    GenerationMismatch { memo: u32, manifest: u32 },
    /// The memo pins different bytes than the ones fetched. **A split view**, the
    /// serious answer: report it as such, never as merely unverified.
    SplitView,
    /// The output's recipient is not the issuance address.
    WrongRecipient,
    /// The node could not be asked.
    Oracle(String),
}

impl std::fmt::Display for PinFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinFailure::SidecarGeneration { sidecar, manifest } => {
                write!(f, "sidecar generation {sidecar} != manifest generation {manifest}")
            }
            PinFailure::TxNotFound => write!(f, "pin transaction not found on the node"),
            PinFailure::NoSuchAction => write!(f, "pin transaction has no such Ironwood Action"),
            PinFailure::OckDoesNotRecover => write!(f, "the OCK does not recover the output"),
            PinFailure::NotAPinMemo => write!(f, "recovered memo is not a pin memo"),
            PinFailure::GenerationMismatch { memo, manifest } => {
                write!(f, "memo pins generation {memo}, manifest says {manifest}")
            }
            PinFailure::SplitView => write!(f, "SPLIT VIEW: the memo pins different manifest bytes"),
            PinFailure::WrongRecipient => write!(f, "pin output is not to the issuance address"),
            PinFailure::Oracle(e) => write!(f, "oracle error: {e}"),
        }
    }
}

impl std::error::Error for PinFailure {}

/// What a verified pin establishes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinVerified {
    pub generation: u32,
    pub height: u32,
    pub manifest_hash: [u8; 32],
}

/// A source of raw mined transactions, for OCK recovery.
pub trait RawTxSource {
    /// The raw transaction bytes and mined height for a display-order txid, if mined.
    fn raw_transaction(&self, txid_display: &[u8; 32]) -> Result<Option<(u32, Vec<u8>)>>;
}

impl RawTxSource for ZebradOracle {
    fn raw_transaction(&self, txid_display: &[u8; 32]) -> Result<Option<(u32, Vec<u8>)>> {
        let v = match self.rpc("getrawtransaction", serde_json::json!([hex(txid_display), 1])) {
            Ok(v) => v,
            Err(e) if e.to_string().contains("node error") => return Ok(None),
            Err(e) => return Err(e),
        };
        let Some(height) = v.get("height").and_then(|h| h.as_u64()) else {
            return Ok(None);
        };
        let hex_tx = v
            .get("hex")
            .and_then(|h| h.as_str())
            .ok_or_else(|| anyhow!("getrawtransaction: no hex"))?;
        Ok(Some((height as u32, decode_hex(hex_tx)?)))
    }
}

/// Verify a sidecar against fetched manifest bytes (`ZMAP-v0.5.md` §7.3.2).
///
/// - `manifest_bytes`: the manifest exactly as fetched.
/// - `manifest_generation`: the `generation` field parsed from it.
/// - `issuance_address`: the Orchard receiver of the address published with `ik`.
pub fn verify_pin(
    manifest_bytes: &[u8],
    manifest_generation: u32,
    sidecar: &PinSidecar,
    issuance_address: &orchard::Address,
    source: &dyn RawTxSource,
    network: Network,
) -> Result<PinVerified, PinFailure> {
    if sidecar.generation != manifest_generation {
        return Err(PinFailure::SidecarGeneration {
            sidecar: sidecar.generation,
            manifest: manifest_generation,
        });
    }
    let txid = decode_hex_32(&sidecar.txid).map_err(|e| PinFailure::Oracle(e.to_string()))?;
    let ock = decode_hex_32(&sidecar.ock).map_err(|e| PinFailure::Oracle(e.to_string()))?;
    let (height, raw) = source
        .raw_transaction(&txid)
        .map_err(|e| PinFailure::Oracle(e.to_string()))?
        .ok_or(PinFailure::TxNotFound)?;
    let branch = BranchId::for_height(&network, BlockHeight::from_u32(height));
    let tx = Transaction::read(&raw[..], branch).map_err(|e| PinFailure::Oracle(e.to_string()))?;
    let action = tx
        .ironwood_bundle()
        .and_then(|b| b.actions().get(sidecar.action_index as usize))
        .ok_or(PinFailure::NoSuchAction)?;

    let domain = IronwoodDomain::for_action(action);
    let (_note, recipient, memo) = try_output_recovery_with_ock(
        &domain,
        &OutgoingCipherKey(ock),
        action,
        &action.encrypted_note().out_ciphertext,
    )
    .ok_or(PinFailure::OckDoesNotRecover)?;

    let (memo_generation, pinned_hash) = parse_pin_memo(&memo).ok_or(PinFailure::NotAPinMemo)?;
    if memo_generation != manifest_generation {
        return Err(PinFailure::GenerationMismatch {
            memo: memo_generation,
            manifest: manifest_generation,
        });
    }
    if pinned_hash != manifest_hash(manifest_bytes) {
        return Err(PinFailure::SplitView);
    }
    if recipient != *issuance_address {
        return Err(PinFailure::WrongRecipient);
    }
    Ok(PinVerified {
        generation: memo_generation,
        height,
        manifest_hash: pinned_hash,
    })
}

/// Fetch a URL's bytes exactly as served (`curl -sfL`). For the "re-hash AFTER
/// deployment" rule: the bytes a CDN hands out, not the bytes on disk.
pub fn fetch_url(url: &str) -> Result<Vec<u8>> {
    let out = Command::new("curl")
        .args(["-sfL", "--max-time", "60", url])
        .output()
        .context("run curl")?;
    if !out.status.success() {
        bail!("curl {url}: exit {}", out.status);
    }
    Ok(out.stdout)
}

/// Decode hex of any length.
pub fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        bail!("odd-length hex");
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).context("hex"))
        .collect()
}

/// Parse an issuance address: a unified address string, or 43 raw Orchard
/// address bytes in hex.
pub fn parse_orchard_address(s: &str, network: Network) -> Result<orchard::Address> {
    let s = s.trim();
    if s.len() == 86 {
        let raw: [u8; 43] = decode_hex(s)?.try_into().map_err(|_| anyhow!("43 bytes expected"))?;
        return Option::from(orchard::Address::from_raw_address_bytes(&raw))
            .ok_or_else(|| anyhow!("not a valid Orchard address"));
    }
    match zcash_keys::address::Address::decode(&network, s) {
        Some(zcash_keys::address::Address::Unified(ua)) => ua
            .orchard()
            .copied()
            .ok_or_else(|| anyhow!("unified address has no Orchard receiver")),
        Some(_) => bail!("not a unified address"),
        None => bail!("could not decode address"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memo_round_trips_and_is_52_bytes_then_nul() {
        let m = pin_memo(7, b"{\"generation\":7}\n");
        assert_eq!(&m[..16], PIN_PREFIX);
        assert!(m[PIN_MEMO_LEN..].iter().all(|&b| b == 0));
        let (g, h) = parse_pin_memo(&m).unwrap();
        assert_eq!(g, 7);
        assert_eq!(h, manifest_hash(b"{\"generation\":7}\n"));
    }

    #[test]
    fn memo_rejects_wrong_prefix_and_trailing_bytes() {
        let mut m = pin_memo(1, b"x");
        m[0] ^= 1;
        assert!(parse_pin_memo(&m).is_none());
        let mut m = pin_memo(1, b"x");
        m[100] = 1;
        assert!(parse_pin_memo(&m).is_none());
    }

    #[test]
    fn one_byte_of_manifest_changes_the_pin() {
        assert_ne!(pin_memo(1, b"abc"), pin_memo(1, b"abc\n"));
        assert_ne!(pin_memo(1, b"abc"), pin_memo(2, b"abc"));
    }

    #[test]
    fn sidecar_generation_is_checked_before_any_network() {
        struct NoNet;
        impl RawTxSource for NoNet {
            fn raw_transaction(&self, _: &[u8; 32]) -> Result<Option<(u32, Vec<u8>)>> {
                panic!("must not be called")
            }
        }
        let sc = PinSidecar {
            generation: 2,
            txid: "00".repeat(32),
            action_index: 0,
            ock: "00".repeat(32),
        };
        let (_, fvk, note) = orchard::note::Note::dummy(&mut rand::rngs::OsRng, None, orchard::note::NoteVersion::V3);
        let _ = fvk;
        let r = verify_pin(b"{}", 3, &sc, &note.recipient(), &NoNet, Network::MainNetwork);
        assert_eq!(
            r,
            Err(PinFailure::SidecarGeneration {
                sidecar: 2,
                manifest: 3
            })
        );
    }

    #[test]
    fn missing_transaction_is_tx_not_found() {
        struct Empty;
        impl RawTxSource for Empty {
            fn raw_transaction(&self, _: &[u8; 32]) -> Result<Option<(u32, Vec<u8>)>> {
                Ok(None)
            }
        }
        let sc = PinSidecar {
            generation: 1,
            txid: "00".repeat(32),
            action_index: 0,
            ock: "00".repeat(32),
        };
        let (_, _, note) = orchard::note::Note::dummy(&mut rand::rngs::OsRng, None, orchard::note::NoteVersion::V3);
        assert_eq!(
            verify_pin(b"{}", 1, &sc, &note.recipient(), &Empty, Network::MainNetwork),
            Err(PinFailure::TxNotFound)
        );
    }
}
