//! The lading: the ordered list of wake proofs delivered with a note
//! (`WAKE-v1.md` §7.2, §7.3; `ZMAP-v0.5.md` §15 calls it the consignment).
//!
//! ```json
//! {
//!   "wake_lading": 1,
//!   "genesis":  { "txid": "<hex, display order>", "action_index": n },
//!   "hops": [
//!     { "kind": "wake-v1", "circuit": "genesis", "instance": ["<anchor>", "<cmx_0>", "<nf>"],
//!       "anchor_height": h, "proof": "<base64>" },
//!     { "kind": "wake-v1", "circuit": "hop", "instance": ["<anchor>", "<nf_prev>", "<nf>"],
//!       "anchor_height": h, "proof": "<base64>" }
//!   ]
//! }
//! ```
//!
//! **`anchor_height` is an addition to `WAKE-v1.md` §7.2.** Every oracle, a full
//! node's `z_gettreestate` and lightwalletd's `GetTreeState` alike, answers "what
//! is the root at height h", never "at what height is this root". A verifier
//! needs the height to check W2 at all, so the prover, who knows it, records it.
//! The value is a hint: the oracle still decides whether the root is real. To be
//! proposed as a v1 erratum.
//!
//! **The lading hash is over the bytes exactly as delivered** (`WAKE-v1.md` §7.3).
//! [`Lading::to_bytes`] produces bytes to deliver; the recipient hashes what it
//! received with [`lading_hash`] and never re-serialises before hashing.
//!
//! A lading MUST NOT be published: its `(nf_prev, nf)` pairs link transactions.

use base64::Engine;
use ff::PrimeField;
use pasta_curves::pallas;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::circuit::{Kind, INSTANCE_LEN};
use crate::keys::KIND_V1;
use crate::oracle::{decode_hex_32, hex};
use crate::prove::WakeProof;

/// The lading format version this crate writes and accepts.
pub const LADING_VERSION: u32 = 1;

/// One wake proof as carried in a lading (`WAKE-v1.md` §7.2 plus `anchor_height`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofEntry {
    /// Always `"wake-v1"` for this crate.
    pub kind: String,
    /// `"genesis"` or `"hop"`.
    pub circuit: String,
    /// `[anchor, nf_prev | cmx_0, nf]`, each 32 bytes canonical little-endian, lower-case hex.
    pub instance: [String; INSTANCE_LEN],
    /// The block height whose end-of-block Ironwood tree has `instance[0]` as its root.
    pub anchor_height: u32,
    /// The Halo 2 transcript bytes, standard base64 with padding.
    pub proof: String,
}

/// The genesis output the chain descends from (`WAKE-v1.md` §7.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    /// Transaction id in display (byte-reversed) order, as explorers and receipts show it.
    pub txid: String,
    /// Index of the Action whose output is the genesis note.
    pub action_index: u32,
}

/// The bill of lading.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lading {
    pub wake_lading: u32,
    pub genesis: Genesis,
    pub hops: Vec<ProofEntry>,
}

/// Why a lading or an entry could not be decoded. Decoding failures are not
/// evidence of forgery; they are evidence of the wrong format or the wrong version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LadingError {
    NotJson(String),
    UnsupportedVersion(u32),
    /// `kind` is not `"wake-v1"`. Verifiers MUST reject unknown kinds rather than guess (§12).
    UnsupportedKind(String),
    UnknownCircuit(String),
    BadHex(usize),
    NonCanonicalInstance(usize),
    BadBase64,
}

impl std::fmt::Display for LadingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LadingError::NotJson(e) => write!(f, "lading is not valid JSON: {e}"),
            LadingError::UnsupportedVersion(v) => write!(f, "unsupported wake_lading version {v}"),
            LadingError::UnsupportedKind(k) => write!(f, "unsupported proof kind {k:?}"),
            LadingError::UnknownCircuit(c) => write!(f, "unknown circuit {c:?}"),
            LadingError::BadHex(i) => write!(f, "instance row {i} is not 64 hex characters"),
            LadingError::NonCanonicalInstance(i) => {
                write!(f, "instance row {i} is not a canonical field element")
            }
            LadingError::BadBase64 => write!(f, "proof is not valid base64"),
        }
    }
}

impl std::error::Error for LadingError {}

impl ProofEntry {
    /// Encode a proof for delivery.
    pub fn from_proof(p: &WakeProof, anchor_height: u32) -> Self {
        let rows = p.instance_bytes();
        ProofEntry {
            kind: KIND_V1.to_string(),
            circuit: p.kind.name().to_string(),
            instance: [hex(&rows[0]), hex(&rows[1]), hex(&rows[2])],
            anchor_height,
            proof: base64::engine::general_purpose::STANDARD.encode(&p.proof),
        }
    }

    /// Which circuit this entry claims. Errors on an unknown kind or circuit name.
    pub fn kind(&self) -> Result<Kind, LadingError> {
        if self.kind != KIND_V1 {
            return Err(LadingError::UnsupportedKind(self.kind.clone()));
        }
        Kind::from_name(&self.circuit).ok_or_else(|| LadingError::UnknownCircuit(self.circuit.clone()))
    }

    /// Decode into a verifiable proof. Rejects non-canonical instance encodings
    /// rather than reducing them (`WAKE-v1.md` §7.1).
    pub fn to_proof(&self) -> Result<WakeProof, LadingError> {
        let kind = self.kind()?;
        let mut instance = [pallas::Base::zero(); INSTANCE_LEN];
        for (i, row) in self.instance.iter().enumerate() {
            let bytes = decode_hex_32(row).map_err(|_| LadingError::BadHex(i))?;
            let f: Option<pallas::Base> = pallas::Base::from_repr(bytes).into();
            instance[i] = f.ok_or(LadingError::NonCanonicalInstance(i))?;
        }
        let proof = base64::engine::general_purpose::STANDARD
            .decode(&self.proof)
            .map_err(|_| LadingError::BadBase64)?;
        Ok(WakeProof {
            kind,
            instance,
            proof,
        })
    }
}

impl Lading {
    /// A new lading for `genesis` with no hops yet.
    pub fn new(genesis_txid_hex: &str, action_index: u32) -> Self {
        Lading {
            wake_lading: LADING_VERSION,
            genesis: Genesis {
                txid: genesis_txid_hex.to_string(),
                action_index,
            },
            hops: Vec::new(),
        }
    }

    /// Parse delivered bytes. Version and canonical form (`WAKE-v1.md` §7.3) are checked
    /// here; everything else in `verify_chain`. Canonical form means: these bytes are exactly
    /// what `to_bytes` writes for their content (member order, indentation, lower-case hex,
    /// no unknown members). Until 2026-10-08 nothing checked it, so upper-case hex or an
    /// extra member passed, and a lading rebuilt from knots then hashed differently and
    /// showed as Broken (audit, WAKE F-7, Knotline F).
    pub fn parse(bytes: &[u8]) -> Result<Lading, LadingError> {
        let l: Lading =
            serde_json::from_slice(bytes).map_err(|e| LadingError::NotJson(e.to_string()))?;
        if l.wake_lading != LADING_VERSION {
            return Err(LadingError::UnsupportedVersion(l.wake_lading));
        }
        if l.to_bytes() != bytes {
            return Err(LadingError::NotJson("not in canonical form (WAKE-v1 section 7.3)".into()));
        }
        // `to_bytes` writes strings as they are, so the round trip above does not see the
        // case of hex or the padding of base64; section 7.3 fixes both (lower case; standard
        // base64 with padding), and a lading rebuilt from knots is written that way, so one
        // written otherwise would hash differently and show as Broken at its recipient
        // (review 2026-10-09, regression Finding 6).
        let lower_hex = |s: &str| s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !lower_hex(&l.genesis.txid) {
            return Err(LadingError::NotJson("genesis.txid is not 64 lower-case hex characters (WAKE-v1 section 7.3)".into()));
        }
        for (j, h) in l.hops.iter().enumerate() {
            if !h.instance.iter().all(|r| lower_hex(r)) {
                return Err(LadingError::NotJson(format!("hops[{j}].instance is not lower-case hex (WAKE-v1 section 7.3)")));
            }
            if h.proof.len() % 4 != 0
                || !h.proof.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
                || h.proof.trim_end_matches('=').contains('=')
                || h.proof.len() - h.proof.trim_end_matches('=').len() > 2
            {
                return Err(LadingError::NotJson(format!("hops[{j}].proof is not standard base64 with padding (WAKE-v1 section 7.3)")));
            }
        }
        Ok(l)
    }

    /// Bytes to deliver. Hash *these* bytes (or the bytes received), never a re-serialisation.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(self).expect("lading serialises")
    }
}

/// `SHA-256` over the lading bytes exactly as delivered (`WAKE-v1.md` §7.3;
/// `ZMAP-v0.5.md` §15 `consignment_hash`).
pub fn lading_hash(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_form_fixes_hex_case_and_base64_padding() {
        // WAKE-v1 §7.3: lower-case hex, standard base64 with padding. Until 2026-10-09 the
        // round-trip check saw neither (review, regression Finding 6).
        let p = WakeProof {
            kind: Kind::Genesis,
            // A value whose hex has letters, so upper-casing it changes the text.
            instance: [pallas::Base::from(0xabc_def), pallas::Base::from(2), pallas::Base::from(3)],
            proof: vec![7u8; 10],
        };
        let mut l = Lading::new(&"ab".repeat(32), 0);
        l.hops.push(ProofEntry::from_proof(&p, 1));
        let good = l.to_bytes();
        assert!(Lading::parse(&good).is_ok());
        let upper_txid = String::from_utf8(good.clone()).unwrap().replacen(&"ab".repeat(32), &"AB".repeat(32), 1);
        assert!(Lading::parse(upper_txid.as_bytes()).is_err(), "upper-case genesis txid");
        let mut u = l.clone();
        u.hops[0].instance[0] = u.hops[0].instance[0].to_ascii_uppercase();
        assert!(Lading::parse(&u.to_bytes()).is_err(), "upper-case instance hex");
        let mut np = l.clone();
        np.hops[0].proof = np.hops[0].proof.trim_end_matches('=').to_string();
        assert_ne!(np.hops[0].proof, l.hops[0].proof, "the fixture proof is padded");
        assert!(Lading::parse(&np.to_bytes()).is_err(), "unpadded base64");
    }

    #[test]
    fn entry_round_trips() {
        let p = WakeProof {
            kind: Kind::Hop,
            instance: [pallas::Base::from(1), pallas::Base::from(2), pallas::Base::from(3)],
            proof: vec![1, 2, 3, 4, 5],
        };
        let e = ProofEntry::from_proof(&p, 42);
        assert_eq!(e.circuit, "hop");
        assert_eq!(e.kind, "wake-v1");
        assert_eq!(e.to_proof().unwrap(), p);
    }

    #[test]
    fn unknown_kind_and_circuit_are_rejected() {
        let mut e = ProofEntry::from_proof(
            &WakeProof {
                kind: Kind::Genesis,
                instance: [pallas::Base::zero(); 3],
                proof: vec![],
            },
            1,
        );
        e.kind = "wake-v2".into();
        assert_eq!(e.kind(), Err(LadingError::UnsupportedKind("wake-v2".into())));
        e.kind = "wake-v1".into();
        e.circuit = "hop2".into();
        assert_eq!(e.kind(), Err(LadingError::UnknownCircuit("hop2".into())));
    }

    #[test]
    fn non_canonical_instance_is_rejected() {
        let mut e = ProofEntry::from_proof(
            &WakeProof {
                kind: Kind::Hop,
                instance: [pallas::Base::zero(); 3],
                proof: vec![],
            },
            1,
        );
        e.instance[2] = "ff".repeat(32);
        assert_eq!(e.to_proof(), Err(LadingError::NonCanonicalInstance(2)));
    }

    #[test]
    fn hash_is_over_delivered_bytes_not_a_reserialisation() {
        let l = Lading::new("00".repeat(32).as_str(), 0);
        let a = l.to_bytes();
        let mut b = a.clone();
        b.push(b'\n'); // one byte of whitespace changes the hash
        assert_ne!(lading_hash(&a), lading_hash(&b));
        assert!(Lading::parse(&a).is_ok());
        // 2026-10-08: and such bytes are not a lading at all; only the canonical form is read.
        assert!(matches!(Lading::parse(&b), Err(LadingError::NotJson(_))));
        let mut v = l.clone();
        v.wake_lading = 2;
        assert_eq!(
            Lading::parse(&v.to_bytes()),
            Err(LadingError::UnsupportedVersion(2))
        );
    }
}
