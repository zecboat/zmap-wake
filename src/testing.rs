//! Fixtures for tests and benchmarks. Not for production use.
//!
//! A fixture is one real note (random keys, chosen version and value, chosen
//! `ρ`) placed alone in an otherwise-empty note-commitment tree, with its
//! authentication path and the resulting anchor. This is the shape Zcash Coin
//! Voting's `real_proof_roundtrip` test uses
//! (`voting-circuits-0.12.1/src/delegation/prove.rs:305-335`).

use incrementalmerkletree::{Hashable, Level};
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use orchard::note::{ExtractedNoteCommitment, Note, NoteVersion, Rho};
use orchard::tree::{Anchor, MerkleHashOrchard, MerklePath};
use orchard::value::NoteValue;
use orchard::NOTE_COMMITMENT_TREE_DEPTH as DEPTH;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::witness::Witness;

/// A note in a tree, with everything needed to prove it.
#[derive(Clone, Debug)]
pub struct Fixture {
    pub sk: SpendingKey,
    pub fvk: FullViewingKey,
    pub note: Note,
    pub path: MerklePath,
    pub anchor: Anchor,
    pub witness: Witness,
}

/// A fresh random spending key and its full viewing key.
pub fn random_keys() -> (SpendingKey, FullViewingKey) {
    let sk = SpendingKey::random(&mut OsRng);
    let fvk = FullViewingKey::from(&sk);
    (sk, fvk)
}

/// A random `ρ` that is a real nullifier (of a throwaway note), as every
/// non-genesis note's `ρ` is.
pub fn random_rho() -> Rho {
    let (_, fvk, dummy) = Note::dummy(&mut OsRng, None, NoteVersion::V3);
    Rho::from_nf_old(dummy.nullifier(&fvk))
}

/// A note to `fvk`'s external address 0 with the given fields and fresh randomness.
pub fn note_to(fvk: &FullViewingKey, value: u64, rho: Rho, version: NoteVersion) -> Note {
    let recipient = fvk.address_at(0u32, Scope::External);
    Note::new(
        recipient,
        NoteValue::from_raw(value),
        rho,
        version,
        &mut OsRng,
    )
}

/// The authentication path of a leaf at `position` in a tree that holds only
/// that leaf, and the root of that tree.
pub fn lone_leaf_path(cmx: &ExtractedNoteCommitment, position: u32) -> (MerklePath, Anchor) {
    let empty = MerkleHashOrchard::empty_leaf();
    let mut auth_path = [empty; DEPTH];
    for (level, sibling) in auth_path.iter_mut().enumerate() {
        *sibling = MerkleHashOrchard::empty_root(Level::from(level as u8));
    }
    let path = MerklePath::from_parts(position, auth_path);
    let anchor = path.root(*cmx);
    (path, anchor)
}

/// A complete fixture: random keys, a note of `version` and `value` with `rho`
/// (random if `None`), alone in a tree at a random position.
pub fn fixture(version: NoteVersion, value: u64, rho: Option<Rho>) -> Fixture {
    let (sk, fvk) = random_keys();
    let rho = rho.unwrap_or_else(random_rho);
    let note = note_to(&fvk, value, rho, version);
    let cmx = ExtractedNoteCommitment::from(note.commitment());
    let position = OsRng.next_u32();
    let (path, anchor) = lone_leaf_path(&cmx, position);
    let witness = Witness::from_note(&note, &fvk, &path);
    Fixture {
        sk,
        fvk,
        note,
        path,
        anchor,
        witness,
    }
}

/// A 10,000-zatoshi V3 note: the ZMAP carrier shape.
pub fn carrier() -> Fixture {
    fixture(NoteVersion::V3, 10_000, None)
}
