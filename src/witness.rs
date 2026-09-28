//! The Wake witness: private inputs of `WAKE_HOP` and `WAKE_GENESIS`.
//!
//! `WAKE-v1.md` §6 (normative for interoperability):
//!
//! | Field        | Derivation                                                        |
//! |--------------|-------------------------------------------------------------------|
//! | `g_d`, `pk_d`| from the note's recipient address                                  |
//! | `ψ`          | `PRF^expand_rseed([0x09] ‖ ρ)` → `ToBase`                           |
//! | `rcm`        | V2: `PRF^expand_rseed([0x05] ‖ ρ)` → `ToScalar`; V3: ZIP 2005 form |
//! | `nk`         | `FullViewingKey::nk()`; never re-derived from the spending key      |
//! | `path`, `pos`| the note's authentication path at `anchor`                          |
//!
//! Every field is taken from `orchard 0.15.3` under `unstable-voting-circuits`,
//! the same way the Coin Voting delegation circuit does
//! (`voting-circuits-0.12.1/src/delegation/circuit.rs:120-160`).
//!
//! [`Witness::commitment`] and [`Witness::nullifier`] recompute `cm` and `nf`
//! from the witness fields **without** calling `Note::commitment()` or
//! `Note::nullifier()`, using the Sinsemilla and Poseidon primitives directly
//! with the layout of Protocol Spec §5.4.8.4 and §4.16. The tests then compare
//! against the library. A wrong `rcm` derivation does not produce an invalid
//! proof; it produces a valid proof of a note that is not in the tree, which
//! fails at verification with no indication of why (`WAKE-v1.md` §6). These
//! tests are the only place that mistake is caught early.

use ff::PrimeField;
use group::{Curve, GroupEncoding};
use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as PoseidonHash, P128Pow5T3};
use orchard::keys::{DiversifiedTransmissionKey, FullViewingKey, NullifierDerivingKey};
use orchard::note::{ExtractedNoteCommitment, Note, NoteCommitTrapdoor, NoteVersion, Rho};
use orchard::spec::NonIdentityPallasPoint;
use orchard::tree::{Anchor, MerkleHashOrchard, MerklePath};
use orchard::value::NoteValue;
use orchard::{L_ORCHARD_BASE, L_VALUE, NOTE_COMMITMENT_TREE_DEPTH as MERKLE_DEPTH_ORCHARD};
use pasta_curves::arithmetic::{CurveAffine, CurveExt};
use pasta_curves::pallas;
use subtle::CtOption;

/// `NoteCommit^Orchard` Sinsemilla commit domain (Protocol Spec §5.4.8.4).
/// Stated here as a literal on purpose: this module must not borrow the
/// library's constant, or the equivalence test proves nothing about the domain.
pub const NOTE_COMMIT_DOMAIN: &str = "z.cash:Orchard-NoteCommit";

/// The private inputs of one Wake proof, for one note.
///
/// Field types are orchard's own so chapter 4 can hand them to orchard's
/// gadgets exactly as the Action circuit does (`orchard/src/circuit.rs:180-195`).
#[derive(Clone, Debug)]
pub struct Witness {
    /// Diversified base of the recipient address.
    pub g_d: NonIdentityPallasPoint,
    /// Diversified transmission key of the recipient address.
    pub pk_d: DiversifiedTransmissionKey,
    /// Note value in zatoshi.
    pub value: NoteValue,
    /// The note's ρ. For a hop this must equal the previous nullifier.
    pub rho: Rho,
    /// ψ, derived from `rseed` and ρ.
    pub psi: pallas::Base,
    /// The commitment trapdoor, derived per note version.
    pub rcm: NoteCommitTrapdoor,
    /// The holder's nullifier-deriving key. Never leaves the witness.
    pub nk: NullifierDerivingKey,
    /// Authentication path from the leaf to the anchor, leaf-side first.
    pub path: [MerkleHashOrchard; MERKLE_DEPTH_ORCHARD],
    /// Leaf position in the note-commitment tree.
    pub pos: u32,
    /// Which `rcm` derivation applies. Not a circuit input; recorded so the
    /// witness is self-describing.
    pub version: NoteVersion,
}

impl Witness {
    /// Derive the witness from a decrypted note, the holder's full viewing key,
    /// and the note's authentication path at the anchor the proof will use.
    pub fn from_note(note: &Note, fvk: &FullViewingKey, path: &MerklePath) -> Self {
        let recipient = note.recipient();
        let g_d = recipient.g_d();
        let pk_d = *recipient.pk_d();
        let value = note.value();
        let rho = note.rho();
        let rseed = note.rseed();
        let version = note.version();

        let psi = rseed.psi(&rho);
        let rcm = match version {
            NoteVersion::V2 => rseed.rcm_v2(&rho),
            NoteVersion::V3 => rseed.rcm_v3(&rho, &g_d, &pk_d.inner(), value.inner(), &psi),
        };

        Witness {
            g_d,
            pk_d,
            value,
            rho,
            psi,
            rcm,
            nk: *fvk.nk(),
            path: path.auth_path(),
            pos: path.position(),
            version,
        }
    }

    /// `NoteCommit^Orchard_rcm(g_d, pk_d, v, ρ, ψ)` recomputed from the witness
    /// fields with the Sinsemilla primitive. `None` if the commitment is ⊥.
    pub fn commitment(&self) -> CtOption<pallas::Point> {
        let domain = sinsemilla::CommitDomain::new(NOTE_COMMIT_DOMAIN);
        let g_d_bytes = self.g_d.to_bytes();
        let pk_d_bytes = self.pk_d.inner().to_bytes();
        let value_bytes = self.value.inner().to_le_bytes();
        let rho_repr = self.rho.into_inner().to_repr();
        let psi_repr = self.psi.to_repr();
        let msg = bits_le(&g_d_bytes)
            .chain(bits_le(&pk_d_bytes))
            .chain(bits_le(&value_bytes).take(L_VALUE))
            .chain(bits_le(&rho_repr).take(L_ORCHARD_BASE))
            .chain(bits_le(&psi_repr).take(L_ORCHARD_BASE));
        domain.commit(msg, &self.rcm.inner())
    }

    /// `Extract_P(cm)`: the x-coordinate of the commitment. `None` if `cm` is ⊥.
    pub fn cmx(&self) -> CtOption<pallas::Base> {
        self.commitment().map(|cm| extract_p(&cm))
    }

    /// `DeriveNullifier_nk(ρ, ψ, cm)` recomputed with the Poseidon primitive
    /// (Protocol Spec §4.16):
    /// `Extract_P([ (PRF^nfOrchard_nk(ρ) + ψ) mod r_P ] K^Orchard + cm)`.
    pub fn nullifier(&self) -> CtOption<pallas::Base> {
        self.commitment()
            .map(|cm| derive_nullifier(self.nk.inner(), self.rho.into_inner(), self.psi, &cm))
    }

    /// The root the path leads to from this note's `cmx`. The verifier decides
    /// whether it is a real anchor; the witness only computes it.
    pub fn anchor(&self) -> CtOption<Anchor> {
        self.cmx().map(|cmx| {
            let cmx = ExtractedNoteCommitment::from_bytes(&cmx.to_repr())
                .expect("cmx came from a valid base field element");
            MerklePath::from_parts(self.pos, self.path).root(cmx)
        })
    }
}

/// `DeriveNullifier_nk(ρ, ψ, cm)` over raw field elements (Protocol Spec §4.16):
/// `Extract_P([ (PRF^nfOrchard_nk(ρ) + ψ) mod r_P ] K^Orchard + cm)`.
/// Public so tests can compute the nullifier an attacker's *claimed* `ρ` implies.
pub fn derive_nullifier(
    nk: pallas::Base,
    rho: pallas::Base,
    psi: pallas::Base,
    cm: &pallas::Point,
) -> pallas::Base {
    let prf =
        PoseidonHash::<pallas::Base, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([nk, rho]);
    let k = pallas::Point::hash_to_curve("z.cash:Orchard")(b"K");
    let scalar = mod_r_p(prf + psi);
    extract_p(&(k * scalar + cm))
}

/// Bits of a byte string, least-significant bit of each byte first.
fn bits_le(bytes: &[u8]) -> impl Iterator<Item = bool> + '_ {
    bytes
        .iter()
        .flat_map(|b| (0..8).map(move |i| (b >> i) & 1 == 1))
}

/// `x mod r_P` for `x` in the base field. No reduction is needed because
/// Pallas' base field is smaller than its scalar field (`orchard/src/spec.rs:204`).
fn mod_r_p(x: pallas::Base) -> pallas::Scalar {
    pallas::Scalar::from_repr(x.to_repr()).expect("p < r, so every base repr is a scalar repr")
}

/// Coordinate extractor for Pallas (Protocol Spec §5.4.9.7): `x`, or 0 for the identity.
fn extract_p(point: &pallas::Point) -> pallas::Base {
    point
        .to_affine()
        .coordinates()
        .map(|c| *c.x())
        .unwrap_or_else(pallas::Base::zero)
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::note::RandomSeed;
    use orchard::Address;
    use rand::rngs::OsRng;
    use rand::RngCore;

    fn dummy_note(version: NoteVersion) -> (FullViewingKey, Note) {
        let mut rng = OsRng;
        let (_sk, fvk, note) = Note::dummy(&mut rng, None, version);
        (fvk, note)
    }

    fn some_path() -> MerklePath {
        MerklePath::dummy(&mut OsRng)
    }

    /// The witness's own commitment equals the library's, for both note versions.
    #[test]
    fn commitment_matches_library_v2_and_v3() {
        for version in [NoteVersion::V2, NoteVersion::V3] {
            for _ in 0..8 {
                let (fvk, note) = dummy_note(version);
                let w = Witness::from_note(&note, &fvk, &some_path());
                let ours = w.commitment().unwrap();
                assert_eq!(ours, note.commitment().inner(), "cm, {version:?}");
                let ours_x = w.cmx().unwrap();
                let lib_x = ExtractedNoteCommitment::from(note.commitment()).inner();
                assert_eq!(ours_x, lib_x, "cmx, {version:?}");
            }
        }
    }

    /// The witness's own nullifier equals the library's, for both note versions.
    #[test]
    fn nullifier_matches_library_v2_and_v3() {
        for version in [NoteVersion::V2, NoteVersion::V3] {
            for _ in 0..8 {
                let (fvk, note) = dummy_note(version);
                let w = Witness::from_note(&note, &fvk, &some_path());
                let ours = w.nullifier().unwrap();
                assert_eq!(ours, note.nullifier(&fvk).inner(), "nf, {version:?}");
            }
        }
    }

    /// `nk` is taken from the FVK's public accessor and equals bytes 32..64 of
    /// the raw FVK encoding (Protocol Spec §5.6.4.4), the fallback `WAKE-v1.md` §6 allows.
    #[test]
    fn nk_is_fvk_bytes_32_to_64() {
        let (fvk, note) = dummy_note(NoteVersion::V3);
        let w = Witness::from_note(&note, &fvk, &some_path());
        assert_eq!(w.nk.inner().to_repr(), fvk.to_bytes()[32..64]);
    }

    /// Non-zero value notes, not only the zero-value dummies, must reproduce too:
    /// `v` is part of the commitment and of the V3 `rcm` preimage.
    #[test]
    fn nonzero_value_notes_match_library() {
        let mut rng = OsRng;
        for version in [NoteVersion::V2, NoteVersion::V3] {
            let (fvk, dummy) = dummy_note(version);
            let recipient: Address = dummy.recipient();
            // A real nullifier as ρ, the way every non-genesis note gets one.
            let rho = Rho::from_nf_old(dummy.nullifier(&fvk));
            let value = NoteValue::from_raw(10_000);
            let note = loop {
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed);
                let rseed = RandomSeed::from_bytes(seed, &rho);
                if bool::from(rseed.is_none()) {
                    continue;
                }
                let n = Note::from_parts(recipient, value, rho, rseed.unwrap(), version);
                if bool::from(n.is_some()) {
                    break n.unwrap();
                }
            };
            let w = Witness::from_note(&note, &fvk, &some_path());
            assert_eq!(w.commitment().unwrap(), note.commitment().inner());
            assert_eq!(w.nullifier().unwrap(), note.nullifier(&fvk).inner());
        }
    }

    /// The trap `WAKE-v1.md` §6 warns about: the V2 `rcm` derivation applied to a
    /// V3 note yields a commitment that is *valid* but is not the note's. This must
    /// be detectable here, because the circuit cannot detect it.
    #[test]
    fn v2_derivation_on_v3_note_gives_a_different_commitment() {
        let (fvk, note) = dummy_note(NoteVersion::V3);
        let mut w = Witness::from_note(&note, &fvk, &some_path());
        w.rcm = note.rseed().rcm_v2(&note.rho());
        let wrong = w.commitment().unwrap();
        assert_ne!(wrong, note.commitment().inner());
    }

    /// The anchor computed from the witness path equals the library's root for the same path.
    #[test]
    fn anchor_matches_library_root() {
        let (fvk, note) = dummy_note(NoteVersion::V3);
        let path = some_path();
        let w = Witness::from_note(&note, &fvk, &path);
        let lib = path.root(ExtractedNoteCommitment::from(note.commitment()));
        assert_eq!(w.anchor().unwrap(), lib);
    }
}
