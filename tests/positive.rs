//! Chapter 4 positive tests: both circuits satisfy `MockProver` at `K`, real
//! proofs round-trip, keys are distinct, and the verifier is strict about bytes.
//!
//! Negative tests (every case that MUST fail) are chapter 5, `tests/negative.rs`.

use halo2_proofs::dev::{CircuitCost, MockProver};
use orchard::keys::{FullViewingKey, SpendingKey};
use orchard::note::NoteVersion;
use pasta_curves::vesta;
use rand::rngs::OsRng;
use zmap_wake::circuit::{Circuit, INSTANCE_LEN};
use zmap_wake::prove::instance_for;
use zmap_wake::testing::{carrier, fixture};
use zmap_wake::{keys, prove, verify, Kind, K};

fn mock(kind: Kind) {
    let f = carrier();
    let circuit = Circuit::from_witness(kind, &f.witness).unwrap();
    let instance = instance_for(kind, &f.witness).unwrap();
    assert_eq!(instance.len(), INSTANCE_LEN);
    let prover = MockProver::run(K, &circuit, vec![instance.to_vec()]).unwrap();
    prover.assert_satisfied();
}

#[test]
fn mock_prover_hop_satisfied_at_k() {
    mock(Kind::Hop);
}

#[test]
fn mock_prover_genesis_satisfied_at_k() {
    mock(Kind::Genesis);
}

#[test]
fn mock_prover_v2_note_satisfied() {
    let f = fixture(NoteVersion::V2, 10_000, None);
    for kind in [Kind::Hop, Kind::Genesis] {
        let circuit = Circuit::from_witness(kind, &f.witness).unwrap();
        let instance = instance_for(kind, &f.witness).unwrap();
        MockProver::run(K, &circuit, vec![instance.to_vec()])
            .unwrap()
            .assert_satisfied();
    }
}

/// Records the circuit's cost at `K` (chapter 4 box: "CircuitCost and layout recorded").
/// Printed with `--nocapture`; the assertion is only that it fits `K`.
#[test]
fn circuit_cost_recorded() {
    for kind in [Kind::Hop, Kind::Genesis] {
        let cost = CircuitCost::<vesta::Point, Circuit>::measure(K, &Circuit::empty(kind));
        println!("== CircuitCost {} at K={K}\n{cost:#?}", kind.name());
        println!("== proof size (1 instance): {:?}", cost.proof_size(1));
    }
}

#[test]
fn real_proof_roundtrip_hop_and_genesis() {
    let f = carrier();
    let hop = prove::prove_hop(&f.witness).expect("hop proof");
    verify::verify_hop(&hop.proof, &hop.instance).expect("hop verifies");
    let gen = prove::prove_genesis(&f.witness).expect("genesis proof");
    verify::verify_genesis(&gen.proof, &gen.instance).expect("genesis verifies");
    println!(
        "hop proof {} bytes, genesis proof {} bytes",
        hop.proof.len(),
        gen.proof.len()
    );
    assert!(hop.proof.len() < 8192, "proof unexpectedly large");
}

#[test]
fn proof_of_one_kind_does_not_verify_as_the_other() {
    let f = carrier();
    let hop = prove::prove_hop(&f.witness).unwrap();
    // Same bytes, wrong key.
    assert_eq!(
        verify::verify_genesis(&hop.proof, &hop.instance),
        Err(verify::VerifyError::BadProof)
    );
    // Same bytes, right key, the genesis instance (cmx in row 1 instead of rho).
    let gen_instance = instance_for(Kind::Genesis, &f.witness).unwrap();
    assert_eq!(
        verify::verify_hop(&hop.proof, &gen_instance),
        Err(verify::VerifyError::BadProof)
    );
}

#[test]
fn trailing_bytes_are_rejected() {
    let f = carrier();
    let hop = prove::prove_hop(&f.witness).unwrap();
    let mut padded = hop.proof.clone();
    padded.extend_from_slice(b"junk");
    assert_eq!(
        verify::verify_hop(&padded, &hop.instance),
        Err(verify::VerifyError::TrailingBytes(4))
    );
    // Truncation is a bad proof, not a trailing-bytes error.
    let truncated = &hop.proof[..hop.proof.len() - 1];
    assert_eq!(
        verify::verify_hop(truncated, &hop.instance),
        Err(verify::VerifyError::BadProof)
    );
}

#[test]
fn non_canonical_instance_is_rejected() {
    let f = carrier();
    let hop = prove::prove_hop(&f.witness).unwrap();
    let mut rows = hop.instance_bytes();
    // p + 1 is not canonical: set the top byte so the value exceeds the modulus.
    rows[1] = [0xff; 32];
    assert_eq!(
        verify::decode_instance(&rows),
        Err(verify::VerifyError::NonCanonicalInstance(1))
    );
    let good = verify::decode_instance(&hop.instance_bytes()).unwrap();
    assert_eq!(good, hop.instance);
}

#[test]
fn the_two_verifying_keys_differ() {
    assert_ne!(keys::vk_id(Kind::Hop), keys::vk_id(Kind::Genesis));
    println!("vk_id hop     = {}", keys::vk_id_hex(Kind::Hop));
    println!("vk_id genesis = {}", keys::vk_id_hex(Kind::Genesis));
}

/// `nk` is free in `WAKE_HOP` (no `CommitIvk`), so the same note, under the same anchor and
/// with the same `ρ`, has a valid proof for a nullifier the prover chose. This is by design:
/// a later hop needs that nullifier revealed by an Ironwood action, whose own proof binds
/// `nk` to the note's address (`WAKE-v1.md` §9, "A free `nk`…"). Pinned here so nobody reads
/// the negative test `nf_inconsistent_with_witnessed_nk` as "a chosen key is caught"
/// (audit 2026-10-08, WAKE F-8).
#[test]
fn a_chosen_nk_proves_a_different_nf() {
    let f = carrier();
    let real = prove::prove_hop(&f.witness).expect("hop proof");
    let mut w = f.witness.clone();
    w.nk = *FullViewingKey::from(&SpendingKey::random(&mut OsRng)).nk();
    let chosen = prove::prove_hop(&w).expect("hop proof under a chosen nk");
    verify::verify_hop(&chosen.proof, &chosen.instance).expect("a chosen nk verifies");
    // Same anchor and same ρ (the note and its place in the tree are unchanged) ...
    assert_eq!(chosen.instance[0], real.instance[0]);
    assert_eq!(chosen.instance[1], real.instance[1]);
    // ... and a different nullifier.
    assert_ne!(chosen.instance[2], real.instance[2]);
}
