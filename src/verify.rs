//! Proof verification: `verify_hop` and `verify_genesis`.
//!
//! These take a proof and its instance and **check nothing about the chain**.
//! Whether the anchor is a real root and the genesis `cmx` is really at that
//! output is `verify_chain`'s job (chapter 6, `WAKE-v1.md` §8).

use ff::PrimeField;
use halo2_proofs::{
    plonk::{self, SingleVerifier},
    transcript::{Blake2bRead, Challenge255},
};
use pasta_curves::{pallas, vesta};

use crate::circuit::{Kind, INSTANCE_LEN, LINK};
use crate::keys;
use crate::prove::WakeProof;

/// Why a proof did not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The proof does not verify under the key for `kind` and this instance.
    BadProof,
    /// The proof verified but was followed by bytes the verifier did not read.
    /// A proof is exactly its transcript; anything after it is not a proof.
    TrailingBytes(usize),
    /// An instance row is not a canonical field-element encoding (`WAKE-v1.md` §7.1).
    NonCanonicalInstance(usize),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::BadProof => write!(f, "proof does not verify"),
            VerifyError::TrailingBytes(n) => write!(f, "proof has {n} trailing unread bytes"),
            VerifyError::NonCanonicalInstance(i) => {
                write!(f, "instance row {i} is not a canonical field element")
            }
        }
    }
}

impl std::error::Error for VerifyError {}

/// Verify a `WAKE_HOP` proof against `[anchor, nf_prev, nf]`.
pub fn verify_hop(proof: &[u8], instance: &[pallas::Base; INSTANCE_LEN]) -> Result<(), VerifyError> {
    verify(Kind::Hop, proof, instance)
}

/// Verify a `WAKE_GENESIS` proof against `[anchor, cmx_0, nf]`.
pub fn verify_genesis(
    proof: &[u8],
    instance: &[pallas::Base; INSTANCE_LEN],
) -> Result<(), VerifyError> {
    verify(Kind::Genesis, proof, instance)
}

/// Verify `proof` under the key for `kind`. The verifier's `kind` selects the
/// key; a proof carries no key identifier (`WAKE-v1.md` §7.4).
pub fn verify(
    kind: Kind,
    proof: &[u8],
    instance: &[pallas::Base; INSTANCE_LEN],
) -> Result<(), VerifyError> {
    let params = keys::params();
    let vk = &keys::keys(kind).vk;
    let strategy = SingleVerifier::new(params);
    let mut reader = proof;
    let mut transcript = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(&mut reader);
    plonk::verify_proof(params, vk, strategy, &[&[&instance[..]]], &mut transcript)
        .map_err(|_| VerifyError::BadProof)?;
    if !reader.is_empty() {
        return Err(VerifyError::TrailingBytes(reader.len()));
    }
    Ok(())
}

/// Verify a [`WakeProof`] under the key its `kind` names.
pub fn verify_wake_proof(p: &WakeProof) -> Result<(), VerifyError> {
    verify(p.kind, &p.proof, &p.instance)
}

/// Decode instance rows from their 32-byte encodings, rejecting non-canonical
/// ones rather than reducing them (`WAKE-v1.md` §7.1).
pub fn decode_instance(
    rows: &[[u8; 32]; INSTANCE_LEN],
) -> Result<[pallas::Base; INSTANCE_LEN], VerifyError> {
    let mut out = [pallas::Base::zero(); INSTANCE_LEN];
    for (i, row) in rows.iter().enumerate() {
        let f: Option<pallas::Base> = pallas::Base::from_repr(*row).into();
        out[i] = f.ok_or(VerifyError::NonCanonicalInstance(i))?;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Chain verification (WAKE-v1 §8; ZMAP-v0.5 §9 check 7)
// ---------------------------------------------------------------------------

use crate::lading::{lading_hash, Lading, LadingError};
use crate::oracle::{decode_hex_32, AnchorStatus, ChainOracle, MIN_DEPTH};
use orchard::note::Rho;

/// Why a lading did not verify. `GenesisNotOnChain`, `BadProof` and `ChainBreak`
/// are evidence of forgery; the rest are not (`WAKE-v1.md` §8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WakeFailure {
    /// The delivered bytes do not hash to the `consignment_hash` in the memo.
    LadingHashMismatch,
    /// The lading could not be decoded, or breaks a structural MUST of §7.3.
    Malformed(String),
    /// A proof carries a `kind` this verifier does not implement. Never guess (§12).
    UnsupportedProofKind(String),
    /// W1: `hops[0]` is not a genesis proof, or its `cmx_0` is not at the genesis output.
    GenesisNotOnChain,
    /// W2: `hops[j].instance[0]` is not the tree root at `hops[j].anchor_height`.
    AnchorUnknown(usize),
    /// W2: the anchor of hop `j` is only `depth` blocks below the tip. Not wrong; not yet safe.
    AnchorTooShallow { hop: usize, depth: u32 },
    /// W3: the proof of hop `j` does not verify under its circuit's key.
    BadProof(usize),
    /// W4: `hops[j].instance[1] != hops[j-1].instance[2]`.
    ChainBreak(usize),
    /// W5: the note in hand does not have `ρ == hops[last].instance[2]`.
    RhoMismatch,
    /// The oracle could not answer. The asset is *unverified*, not forged.
    Oracle(String),
}

impl std::fmt::Display for WakeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WakeFailure::LadingHashMismatch => write!(f, "lading bytes do not match consignment_hash"),
            WakeFailure::Malformed(s) => write!(f, "malformed lading: {s}"),
            WakeFailure::UnsupportedProofKind(k) => write!(f, "unsupported proof kind {k:?}"),
            WakeFailure::GenesisNotOnChain => write!(f, "genesis cmx is not at the genesis output"),
            WakeFailure::AnchorUnknown(j) => write!(f, "hop {j}: anchor is not a tree root at its height"),
            WakeFailure::AnchorTooShallow { hop, depth } => {
                write!(f, "hop {hop}: anchor only {depth} blocks deep")
            }
            WakeFailure::BadProof(j) => write!(f, "hop {j}: proof does not verify"),
            WakeFailure::ChainBreak(j) => write!(f, "hop {j}: nf_prev is not the previous hop's nf"),
            WakeFailure::RhoMismatch => write!(f, "note rho is not the final hop's nf"),
            WakeFailure::Oracle(e) => write!(f, "oracle error: {e}"),
        }
    }
}

impl std::error::Error for WakeFailure {}

impl From<LadingError> for WakeFailure {
    fn from(e: LadingError) -> Self {
        match e {
            LadingError::UnsupportedKind(k) => WakeFailure::UnsupportedProofKind(k),
            other => WakeFailure::Malformed(other.to_string()),
        }
    }
}

/// What a verified lading establishes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// Number of proofs in the chain, genesis included.
    pub hops: usize,
    /// The genesis output's extracted commitment, as checked against the oracle.
    pub genesis_cmx: [u8; 32],
    /// The final hop's nullifier, which the note in hand has as its `ρ`.
    pub final_nf: [u8; 32],
    /// The shallowest anchor depth seen.
    pub min_anchor_depth: u32,
    /// Whether the oracle self-validated. `ServerAsserted` means: report *unverified*.
    pub trust: crate::oracle::OracleTrust,
}

/// Verify a lading against the note in hand and the verifier's oracle
/// (`WAKE-v1.md` §8, W1–W5, in that order, after the hash and format checks).
///
/// - `lading_bytes`: the bytes exactly as delivered.
/// - `expected_hash`: the memo's `consignment_hash`, if the overlay carries one.
/// - `note_rho`: the `ρ` of the note in hand.
/// - `min_depth`: normally [`MIN_DEPTH`].
///
/// Nullifier-set membership is not checked: membership of `N_{j+1}` with
/// `ρ = nf_j` implies `nf_j` was revealed, by consensus.
///
/// The verifier reports *which* check failed and never succeeds on a subset.
pub fn verify_chain(
    lading_bytes: &[u8],
    expected_hash: Option<[u8; 32]>,
    note_rho: &Rho,
    oracle: &dyn ChainOracle,
    min_depth: u32,
) -> Result<Verified, WakeFailure> {
    if let Some(h) = expected_hash {
        if lading_hash(lading_bytes) != h {
            return Err(WakeFailure::LadingHashMismatch);
        }
    }
    let lading = Lading::parse(lading_bytes)?;
    if lading.hops.is_empty() {
        return Err(WakeFailure::Malformed("no hops".into()));
    }

    // Decode every entry first: kind and circuit names, canonical instances, base64.
    let mut proofs = Vec::with_capacity(lading.hops.len());
    for (j, e) in lading.hops.iter().enumerate() {
        let p = e.to_proof()?;
        let expected = if j == 0 { Kind::Genesis } else { Kind::Hop };
        if p.kind != expected {
            return Err(WakeFailure::Malformed(format!(
                "hops[{j}].circuit is {:?}, expected {:?}",
                p.kind.name(),
                expected.name()
            )));
        }
        proofs.push(p);
    }

    // W1: the genesis cmx is really at the designated output.
    let genesis_txid = decode_hex_32(&lading.genesis.txid)
        .map_err(|e| WakeFailure::Malformed(format!("genesis.txid: {e}")))?;
    let on_chain = oracle
        .cmx_at(&genesis_txid, lading.genesis.action_index)
        .map_err(|e| WakeFailure::Oracle(e.to_string()))?;
    let genesis_cmx = proofs[0].instance[LINK].to_repr();
    match on_chain {
        Some(cmx) if cmx.to_bytes() == genesis_cmx => {}
        _ => return Err(WakeFailure::GenesisNotOnChain),
    }

    // W2: every anchor is a real root at its claimed height, deep enough.
    let mut min_anchor_depth = u32::MAX;
    for (j, (e, p)) in lading.hops.iter().zip(&proofs).enumerate() {
        let root: Option<orchard::tree::Anchor> =
            orchard::tree::Anchor::from_bytes(p.instance[crate::circuit::ANCHOR].to_repr()).into();
        let root = root.ok_or(WakeFailure::AnchorUnknown(j))?;
        match oracle
            .anchor_at(&root, e.anchor_height)
            .map_err(|e| WakeFailure::Oracle(e.to_string()))?
        {
            AnchorStatus::Unknown => return Err(WakeFailure::AnchorUnknown(j)),
            AnchorStatus::Known { depth } if depth < min_depth => {
                return Err(WakeFailure::AnchorTooShallow { hop: j, depth })
            }
            AnchorStatus::Known { depth } => min_anchor_depth = min_anchor_depth.min(depth),
        }
    }

    // W3: every proof verifies under the key for its circuit.
    for (j, p) in proofs.iter().enumerate() {
        verify(p.kind, &p.proof, &p.instance).map_err(|_| WakeFailure::BadProof(j))?;
    }

    // W4: the chain rule.
    for j in 1..proofs.len() {
        if proofs[j].instance[LINK] != proofs[j - 1].instance[crate::circuit::NF] {
            return Err(WakeFailure::ChainBreak(j));
        }
    }

    // W5: the note in hand descends from the last hop.
    let final_nf = proofs.last().unwrap().instance[crate::circuit::NF].to_repr();
    if note_rho.to_bytes() != final_nf {
        return Err(WakeFailure::RhoMismatch);
    }

    Ok(Verified {
        hops: proofs.len(),
        genesis_cmx,
        final_nf,
        min_anchor_depth,
        trust: oracle.trust(),
    })
}

/// [`verify_chain`] with [`MIN_DEPTH`].
pub fn verify_chain_default(
    lading_bytes: &[u8],
    expected_hash: Option<[u8; 32]>,
    note_rho: &Rho,
    oracle: &dyn ChainOracle,
) -> Result<Verified, WakeFailure> {
    verify_chain(lading_bytes, expected_hash, note_rho, oracle, MIN_DEPTH)
}
