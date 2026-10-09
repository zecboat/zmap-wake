//! Chapter 5, "Breaking it": every case that MUST fail (`zecboat_wake_circuit.md`
//! P3, `WAKE-v1.md` §11 item 1).
//!
//! Each case is run three ways, in this order:
//!
//! 1. against the circuit with the constraint it targets **removed**: `MockProver`
//!    must be *satisfied*. This is what makes the case a test and not decoration.
//! 2. against the real circuit under `MockProver`: must fail.
//! 3. as a real proof under the real keys: must not verify.
//!
//! A case that passes step 2 but not step 1 targets the wrong constraint, or two
//! constraints at once; the harness reports which.
//!
//! The instance in every case is what an honest verifier would hold: the true
//! anchor from the oracle, and whatever `nf_prev` / `cmx_0` / `nf` the prover
//! claims. Corruptions are applied to the prover's side (witness or circuit) or
//! to the claim, never to the oracle's anchor except in the "wrong anchor" case.

use ff::{Field, PrimeField};
use halo2_proofs::dev::MockProver;
use orchard::keys::{FullViewingKey, SpendingKey};
use orchard::note::{ExtractedNoteCommitment, NoteVersion};
use orchard::tree::MerkleHashOrchard;
use orchard::value::NoteValue;
use pasta_curves::pallas;
use rand::rngs::OsRng;
use zmap_wake::circuit::{Circuit, Sabotage, ANCHOR, INSTANCE_LEN, LINK, NF};
use zmap_wake::prove::{instance_for, prove_raw};
use zmap_wake::testing::{carrier, fixture, lone_leaf_path, random_rho, Fixture};
use zmap_wake::verify::verify;
use zmap_wake::witness::derive_nullifier;
use zmap_wake::{Kind, K};

type Instance = [pallas::Base; INSTANCE_LEN];

struct Case {
    name: &'static str,
    circuit: Circuit,
    instance: Instance,
    /// The single constraint that catches this case.
    caught_by: Sabotage,
}

fn satisfied(circuit: &Circuit, instance: &Instance) -> bool {
    MockProver::run(K, circuit, vec![instance.to_vec()])
        .expect("synthesis")
        .verify()
        .is_ok()
}

fn check(case: Case) {
    let Case {
        name,
        circuit,
        instance,
        caught_by,
    } = case;

    // 1. Broken circuit: the case must PASS, or it is not testing that constraint.
    let broken = circuit.clone().sabotaged(caught_by);
    assert!(
        satisfied(&broken, &instance),
        "[{name}] still fails with {caught_by:?} removed: the case targets another constraint too"
    );

    // 1b. Sharpness: with any OTHER single constraint removed, it must still fail.
    for other in [
        Sabotage::RootAnchor,
        Sabotage::Nullifier,
        Sabotage::CmEquality,
        Sabotage::Link,
    ] {
        if other == caught_by {
            continue;
        }
        assert!(
            !satisfied(&circuit.clone().sabotaged(other), &instance),
            "[{name}] passes with {other:?} removed, so {other:?} also catches it; caught_by is wrong"
        );
    }

    // 2. Real circuit, MockProver: must fail.
    assert!(
        !satisfied(&circuit, &instance),
        "[{name}] MockProver accepted the real circuit"
    );

    // 3. Real proof, real keys: must not verify.
    let kind = circuit.kind();
    let result = prove_raw(circuit, &instance)
        .map_err(|e| e.to_string())
        .and_then(|p| verify(kind, &p.proof, &p.instance).map_err(|e| e.to_string()));
    match result {
        Ok(()) => panic!("[{name}] a real proof VERIFIED. This is a forgery."),
        // The proof must exist and then be refused by the real verifier. A prover error would
        // mean the tampered witness never reached a verifier, which shows nothing about the
        // constraint under test (review 2026-10-09, suggestion 8).
        Err(e) => assert!(e.contains("does not verify"), "[{name}] failed for an unexpected reason: {e}"),
    }
}

fn honest(kind: Kind, f: &Fixture) -> (Circuit, Instance) {
    (
        Circuit::from_witness(kind, &f.witness).unwrap(),
        instance_for(kind, &f.witness).unwrap(),
    )
}

fn random_base() -> pallas::Base {
    pallas::Base::random(&mut OsRng)
}

fn other_fvk() -> FullViewingKey {
    FullViewingKey::from(&SpendingKey::random(&mut OsRng))
}

// ---------------------------------------------------------------------------
// The ten cases
// ---------------------------------------------------------------------------

/// 1. wrong ρ: instance `nf_prev` ≠ witness ρ.
#[test]
fn wrong_rho_in_instance() {
    let f = carrier();
    let (circuit, mut instance) = honest(Kind::Hop, &f);
    instance[LINK] = random_base();
    check(Case {
        name: "wrong rho",
        circuit,
        instance,
        caught_by: Sabotage::Link,
    });
}

/// 2. ρ right in the instance, wrong inside the commitment.
///
/// The prover holds a real note N' (in the tree, ρ') and claims ρ = nf_prev by
/// overwriting only the witnessed ρ cell. `cm_old` is N''s true commitment, the
/// anchor is true, and the claimed `nf` is what the lie implies, so the only
/// thing that can catch it is `NoteCommit(…, ρ_cell, …) = cm_old`.
#[test]
fn rho_right_in_instance_wrong_inside_commitment() {
    let f = carrier();
    let lie = random_rho();
    let cm_true: pallas::Point = f.witness.commitment().unwrap();
    let nf_of_lie = derive_nullifier(
        f.witness.nk.inner(),
        lie.into_inner(),
        f.witness.psi,
        &cm_true,
    );
    let (circuit, mut instance) = honest(Kind::Hop, &f);
    let circuit = circuit.tamper_rho_old(lie);
    instance[LINK] = lie.into_inner();
    instance[NF] = nf_of_lie;
    check(Case {
        name: "rho wrong inside commitment",
        circuit,
        instance,
        caught_by: Sabotage::CmEquality,
    });
}

/// 3. wrong anchor: a valid path, but the instance carries a root from another tree.
#[test]
fn wrong_anchor() {
    let f = carrier();
    let other = carrier();
    let (circuit, mut instance) = honest(Kind::Hop, &f);
    instance[ANCHOR] = pallas::Base::from_repr_vartime(other.anchor.to_bytes()).unwrap();
    check(Case {
        name: "wrong anchor",
        circuit,
        instance,
        caught_by: Sabotage::RootAnchor,
    });
}

/// 4. wrong path: one sibling altered.
#[test]
fn wrong_path_one_sibling() {
    let f = carrier();
    let (_, instance) = honest(Kind::Hop, &f);
    let mut w = f.witness.clone();
    w.path[7] = MerkleHashOrchard::from_bytes(&random_base().to_repr()).unwrap();
    let circuit = Circuit::from_witness(Kind::Hop, &w).unwrap();
    check(Case {
        name: "wrong path",
        circuit,
        instance,
        caught_by: Sabotage::RootAnchor,
    });
}

/// 5. nf inconsistent with the witnessed nk: a random nullifier-deriving key in the
/// witness, with the instance `nf` derived from the real key.
///
/// This does NOT show that a chosen `nk` is caught: `nk` is free in `WAKE_HOP` by design,
/// and a chosen `nk` with its own `nf` proves (`positive.rs`,
/// `a_chosen_nk_proves_a_different_nf`; `WAKE-v1.md` §9). Named `forged_nk` until
/// 2026-10-08 (audit, WAKE F-8), which suggested otherwise.
#[test]
fn nf_inconsistent_with_witnessed_nk() {
    let f = carrier();
    let (_, instance) = honest(Kind::Hop, &f);
    let mut w = f.witness.clone();
    w.nk = *other_fvk().nk();
    let circuit = Circuit::from_witness(Kind::Hop, &w).unwrap();
    check(Case {
        name: "nf inconsistent with nk",
        circuit,
        instance,
        caught_by: Sabotage::Nullifier,
    });
}

/// 6. nf not from nk: a random instance `nf`.
#[test]
fn random_instance_nf() {
    let f = carrier();
    let (circuit, mut instance) = honest(Kind::Hop, &f);
    instance[NF] = random_base();
    check(Case {
        name: "random nf",
        circuit,
        instance,
        caught_by: Sabotage::Nullifier,
    });
}

/// 7. split attempt: two outputs claiming one `nf_prev`.
///
/// Note A legitimately has ρ_A = nf_prev. Note B is real too, but its ρ_B is
/// some other spend's nullifier (consensus gives every Action one output). A
/// second proof claiming B also descends from nf_prev must fail.
#[test]
fn split_attempt_second_output_claims_same_nf_prev() {
    let nf_prev = random_rho();
    let a = fixture(NoteVersion::V3, 10_000, Some(nf_prev));
    let b = fixture(NoteVersion::V3, 10_000, None); // ρ_B = a different nullifier

    // The legitimate successor proves.
    let (circ_a, inst_a) = honest(Kind::Hop, &a);
    assert!(satisfied(&circ_a, &inst_a));
    assert_eq!(inst_a[LINK], nf_prev.into_inner());

    // The impostor: honest witness for B, but claims A's link.
    let (circ_b, mut inst_b) = honest(Kind::Hop, &b);
    inst_b[LINK] = nf_prev.into_inner();
    check(Case {
        name: "split attempt",
        circuit: circ_b,
        instance: inst_b,
        caught_by: Sabotage::Link,
    });
}

/// 8. wrong genesis: `cmx_0` from a different output.
#[test]
fn wrong_genesis_cmx() {
    let f = carrier();
    let other = carrier();
    let (circuit, mut instance) = honest(Kind::Genesis, &f);
    instance[LINK] = ExtractedNoteCommitment::from(other.note.commitment()).inner();
    check(Case {
        name: "wrong genesis cmx",
        circuit,
        instance,
        caught_by: Sabotage::Link,
    });
}

/// 9. V2 witness for a V3 note.
///
/// `rcm` derived with the wrong version gives a *valid* commitment of a note that
/// does not exist. The prover's circuit is self-consistent (`cm_old`, `nf`, and
/// the path all follow from the wrong `rcm`), so nothing inside the note checks
/// fails. The only thing that catches it is that the leaf is not under the
/// oracle's anchor: exactly the failure `WAKE-v1.md` §6 warns about.
#[test]
fn v2_witness_for_v3_note() {
    let f = carrier();
    assert_eq!(f.note.version(), NoteVersion::V3);
    let mut w = f.witness.clone();
    w.rcm = f.note.rseed().rcm_v2(&f.note.rho());
    let circuit = Circuit::from_witness(Kind::Hop, &w).unwrap();
    // The prover claims the nf its wrong note implies; the verifier holds the true anchor.
    let mut instance = instance_for(Kind::Hop, &w).unwrap();
    instance[ANCHOR] = pallas::Base::from_repr_vartime(f.anchor.to_bytes()).unwrap();
    check(Case {
        name: "V2 witness for V3 note",
        circuit,
        instance,
        caught_by: Sabotage::RootAnchor,
    });
}

/// 10. value tampered: `v` changed with `cm_old` left as the note's real commitment.
#[test]
fn value_tampered() {
    let f = carrier();
    let (circuit, instance) = honest(Kind::Hop, &f);
    let circuit = circuit.tamper_v_old(NoteValue::from_raw(20_000));
    check(Case {
        name: "value tamper",
        circuit,
        instance,
        caught_by: Sabotage::CmEquality,
    });
}

// ---------------------------------------------------------------------------
// Sanity: the harness itself
// ---------------------------------------------------------------------------

/// An honest case is satisfied with or without any sabotage, so the knob cannot
/// turn a valid proof invalid.
#[test]
fn sabotage_never_breaks_an_honest_circuit() {
    let f = carrier();
    for kind in [Kind::Hop, Kind::Genesis] {
        let (circuit, instance) = honest(kind, &f);
        assert!(satisfied(&circuit, &instance));
        for s in [
            Sabotage::RootAnchor,
            Sabotage::Nullifier,
            Sabotage::CmEquality,
            Sabotage::Link,
        ] {
            assert!(satisfied(&circuit.clone().sabotaged(s), &instance), "{kind:?} {s:?}");
        }
    }
}

/// A genesis fixture placed at a different position still verifies (the path
/// position is a witness, not a constant), and the lone-leaf helper agrees with
/// the circuit about where the leaf is.
#[test]
fn position_is_witnessed_not_fixed() {
    let f = carrier();
    let cmx = ExtractedNoteCommitment::from(f.note.commitment());
    for pos in [0u32, 1, 2, u32::MAX] {
        let (path, anchor) = lone_leaf_path(&cmx, pos);
        let w = zmap_wake::Witness::from_note(&f.note, &f.fvk, &path);
        let circuit = Circuit::from_witness(Kind::Genesis, &w).unwrap();
        let mut instance = instance_for(Kind::Genesis, &w).unwrap();
        instance[ANCHOR] = pallas::Base::from_repr_vartime(anchor.to_bytes()).unwrap();
        assert!(satisfied(&circuit, &instance), "pos {pos}");
    }
}
