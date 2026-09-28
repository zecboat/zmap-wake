//! Proof creation: `prove_hop` and `prove_genesis`.

use ff::PrimeField;
use halo2_proofs::{
    plonk,
    transcript::{Blake2bWrite, Challenge255},
};
use pasta_curves::{pallas, vesta};
use rand::rngs::OsRng;

use crate::circuit::{Circuit, Kind, ANCHOR, INSTANCE_LEN, LINK, NF};
use crate::keys;
use crate::witness::Witness;

/// One Wake proof with the public inputs it was made for.
///
/// `instance` is `[anchor, nf_prev | cmx_0, nf]` in that order (`WAKE-v1.md` §5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WakeProof {
    pub kind: Kind,
    pub instance: [pallas::Base; INSTANCE_LEN],
    pub proof: Vec<u8>,
}

impl WakeProof {
    /// Instance rows as canonical 32-byte little-endian encodings (`WAKE-v1.md` §7.1).
    pub fn instance_bytes(&self) -> [[u8; 32]; INSTANCE_LEN] {
        [
            self.instance[ANCHOR].to_repr(),
            self.instance[LINK].to_repr(),
            self.instance[NF].to_repr(),
        ]
    }
}

/// Why a proof could not be made.
#[derive(Debug)]
pub enum ProveError {
    /// The witness's commitment is ⊥; no such note exists.
    NoCommitment,
    /// Halo 2 rejected the witness (a constraint is unsatisfied, or a value is unknown).
    Halo2(plonk::Error),
}

impl std::fmt::Display for ProveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProveError::NoCommitment => write!(f, "witness has no note commitment"),
            ProveError::Halo2(e) => write!(f, "halo2 proof creation failed: {e:?}"),
        }
    }
}

impl std::error::Error for ProveError {}

/// The public inputs a witness implies for `kind`: its anchor, its link value
/// (`ρ` for a hop, `cmx` for genesis), and its nullifier. `None` if the
/// commitment is ⊥.
pub fn instance_for(kind: Kind, w: &Witness) -> Option<[pallas::Base; INSTANCE_LEN]> {
    let anchor: Option<orchard::tree::Anchor> = w.anchor().into();
    let cmx: Option<_> = w.cmx().into();
    let nf: Option<_> = w.nullifier().into();
    let link = match kind {
        Kind::Hop => w.rho.into_inner(),
        Kind::Genesis => cmx?,
    };
    let mut inst = [pallas::Base::zero(); INSTANCE_LEN];
    inst[ANCHOR] = pallas::Base::from_repr(anchor?.to_bytes()).unwrap();
    inst[LINK] = link;
    inst[NF] = nf?;
    Some(inst)
}

/// Prove that `w` is a note in the tree at its anchor whose `ρ` is the
/// instance's `nf_prev` and whose nullifier is the instance's `nf`.
pub fn prove_hop(w: &Witness) -> Result<WakeProof, ProveError> {
    prove(Kind::Hop, w)
}

/// Prove that `w` is a note in the tree at its anchor whose `cmx` is the
/// instance's `cmx_0` and whose nullifier is the instance's `nf`.
pub fn prove_genesis(w: &Witness) -> Result<WakeProof, ProveError> {
    prove(Kind::Genesis, w)
}

/// Prove `kind` for `w`. The instance is derived from the witness, never supplied.
pub fn prove(kind: Kind, w: &Witness) -> Result<WakeProof, ProveError> {
    let instance = instance_for(kind, w).ok_or(ProveError::NoCommitment)?;
    let circuit = Circuit::from_witness(kind, w).ok_or(ProveError::NoCommitment)?;
    let proof = create_proof_bytes(kind, circuit, &instance)?;
    Ok(WakeProof {
        kind,
        instance,
        proof,
    })
}

/// Prove an arbitrary circuit against an arbitrary instance. **Test-only**: the
/// production API derives the instance from the witness; this lets a negative
/// test hand the prover a lie and check the verifier rejects it.
#[cfg(feature = "sabotage")]
pub fn prove_raw(
    circuit: Circuit,
    instance: &[pallas::Base; INSTANCE_LEN],
) -> Result<WakeProof, ProveError> {
    let kind = circuit.kind();
    let proof = create_proof_bytes(kind, circuit, instance)?;
    Ok(WakeProof {
        kind,
        instance: *instance,
        proof,
    })
}

/// Run the prover over one circuit and one instance column.
pub(crate) fn create_proof_bytes(
    kind: Kind,
    circuit: Circuit,
    instance: &[pallas::Base; INSTANCE_LEN],
) -> Result<Vec<u8>, ProveError> {
    let params = keys::params();
    let pk = &keys::keys(kind).pk;
    let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(vec![]);
    plonk::create_proof(
        params,
        pk,
        &[circuit],
        &[&[&instance[..]]],
        OsRng,
        &mut transcript,
    )
    .map_err(ProveError::Halo2)?;
    Ok(transcript.finalize())
}
