//! zmap-wake — proofs of note lineage on Zcash (WAKE v1).
//!
//! Separate exploratory project; see `../README.md`. This crate depends only on
//! crates.io, pinned to the versions in the Zecboat wallet's lock file, and never
//! reads a live wallet.
//!
//! What is here, by chapter of `wake_chapters.md`:
//!
//! - **3, the witness.** [`witness::Witness`]: the private inputs of `WAKE_HOP` /
//!   `WAKE_GENESIS`, derived from a decrypted note and a full viewing key exactly
//!   as `WAKE-v1.md` §6 specifies, with an independent off-circuit recomputation
//!   of the note commitment and nullifier. [`wallet_path`]: Merkle paths at a past
//!   anchor from a *copy* of a wallet database.
//! - **4, the two circuits.** [`circuit`]: the Action circuit's spend half with one
//!   public input added, derived from `orchard/src/circuit.rs` by deletion.
//!   [`keys`]: cached keys and the `vk_id`. [`prove`] and [`verify`].
//! - **6, the lading and the verifier.** [`lading`]: the delivered format and its hash.
//!   [`oracle`]: the [`oracle::ChainOracle`] trait and a zebrad implementation.
//!   [`verify::verify_chain`]: W1–W5 with named failures.
//! - **7, tool.** `tests/mainnet_wake_test_001.rs` (ignored; needs a zebrad, and wallet COPIES to rebuild).
//! - **9, the issuer side.** [`wallet_notes`]: notes and witnesses from a wallet COPY.
//!   [`pin`]: the §7.3 on-chain manifest pin. [`attest`]: the bridge attestation.
//!   [`manifest`]: `ik` and `genesis[]`. The `wake-issuer` binary drives them.
//! - [`testing`]: fixtures. Not for production use.
//!
//! Status: DRAFT, no external review. A missing constraint here is a forgery.
//! Nothing that depends on this crate may report "verified" before
//! `WAKE-v1.md` §11 has happened.

#![deny(unsafe_code)]

pub mod attest;
pub mod circuit;
pub mod keys;
pub mod lading;
pub mod manifest;
pub mod oracle;
#[cfg(feature = "lightwalletd")]
pub mod oracle_lightwalletd;
pub mod pin;
pub mod prove;
pub mod seal;
pub mod testing;
pub mod verify;
pub mod wallet_notes;
pub mod wallet_path;
pub mod witness;

pub use circuit::{Kind, K};
pub use prove::{prove_genesis, prove_hop, WakeProof};
pub use verify::{verify_chain, verify_genesis, verify_hop, Verified, VerifyError, WakeFailure};
pub use witness::Witness;

/// Compile-time proof that every orchard internal Wake needs is reachable under
/// the `unstable-voting-circuits` feature. If this stops compiling, the feature
/// moved: pin `orchard` harder or vendor (`zecboat_wake_circuit.md` §5).
#[allow(unused_imports, dead_code)]
mod feature_gate {
    use halo2_gadgets::sinsemilla::merkle::MerklePath as _;
    use orchard::circuit::commit_ivk::CommitIvkChip as _;
    use orchard::circuit::gadget::{assign_free_advice as _, derive_nullifier as _};
    use orchard::circuit::note_commit::NoteCommitChip as _;
    use orchard::constants::{
        OrchardCommitDomains as _, OrchardFixedBases as _, OrchardHashDomains as _,
    };

    pub fn nk_is_public(
        fvk: &orchard::keys::FullViewingKey,
    ) -> orchard::keys::NullifierDerivingKey {
        *fvk.nk()
    }
}
