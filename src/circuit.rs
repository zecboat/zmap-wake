//! The Wake circuits: `WAKE_HOP` and `WAKE_GENESIS` (`WAKE-v1.md` §4, §5).
//!
//! **Derived from `orchard 0.15.3` `src/circuit.rs` by deletion**, so a reviewer
//! can diff (`docs/diff_vs_orchard_circuit.md`). Names are orchard's (`*_old` is
//! the spent note, the only note Wake has). Relative to the Action circuit's
//! spend half:
//!
//! Deleted:
//! - the output note entirely (`g_d_new`, `pk_d_new`, `v_new`, `psi_new`, `rcm_new`, `cmx`);
//! - value commitment (`v_net`, `rcv`, `cv_net`);
//! - spend authority (`alpha`, `ak`, `rk`);
//! - diversified address integrity (`rivk`, `CommitIvk`, `[ivk] g_d`); `pk_d_old` is witnessed;
//! - the `q_orchard` custom gate and its `enable_spend` / `enable_output` /
//!   `disableCrossAddress` inputs.
//!
//! Changed:
//! - `root = anchor` is unconditional. The Action circuit has
//!   `v_old * (root - anchor) = 0` so zero-value dummies may skip the path;
//!   Wake never proves a dummy, so the root is copy-constrained to the instance.
//!
//! Added, exactly one constraint:
//! - `WAKE_HOP`: the witnessed `rho_old` cell, the same cell that feeds `NoteCommit`
//!   and `DeriveNullifier`, is constrained equal to instance row 1 (`nf_prev`).
//! - `WAKE_GENESIS`: instead, `Extract_P(cm_old)` is constrained equal to instance row 1 (`cmx_0`).
//!
//! Everything else (chips, columns, domains, `K`) is the Action circuit's.
//!
//! Instance column, three rows: `[anchor, nf_prev | cmx_0, nf]` (`WAKE-v1.md` §5).

use group::Curve;
use halo2_gadgets::{
    ecc::{
        chip::{EccChip, EccConfig},
        CircuitVersion, NonIdentityPoint, Point, ScalarFixed,
    },
    poseidon::{primitives as poseidon, Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig},
    sinsemilla::{
        chip::{SinsemillaChip, SinsemillaConfig},
        merkle::{
            chip::{MerkleChip, MerkleConfig},
            MerklePath,
        },
    },
    utilities::lookup_range_check::{LookupRangeCheck, LookupRangeCheckConfig},
};
use halo2_proofs::{
    circuit::{floor_planner, Layouter, Value},
    plonk::{self, Advice, Column, Instance as InstanceColumn},
};
use orchard::{
    circuit::{
        gadget::{
            add_chip::{AddChip, AddConfig},
            assign_free_advice, derive_nullifier, note_commit,
        },
        note_commit::{NoteCommitChip, NoteCommitConfig},
    },
    constants::{OrchardCommitDomains, OrchardFixedBases, OrchardHashDomains},
    keys::{DiversifiedTransmissionKey, NullifierDerivingKey},
    note::{NoteCommitTrapdoor, Rho},
    spec::NonIdentityPallasPoint,
    tree::MerkleHashOrchard,
    value::NoteValue,
    NOTE_COMMITMENT_TREE_DEPTH as MERKLE_DEPTH_ORCHARD,
};
use pasta_curves::pallas;

use crate::witness::Witness;

/// Size of the circuit: `2^K` rows. The Action circuit's parameter (`WAKE-v1.md` §5).
pub const K: u32 = 11;

// Absolute offsets for public inputs.
/// Instance row: a note-commitment-tree root.
pub const ANCHOR: usize = 0;
/// Instance row: `nf_prev` for `WAKE_HOP`, `cmx_0` for `WAKE_GENESIS`.
pub const LINK: usize = 1;
/// Instance row: this note's nullifier.
pub const NF: usize = 2;
/// Number of instance rows.
pub const INSTANCE_LEN: usize = 3;

/// Which of the two Wake relations a circuit instance proves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// `rho_old = nf_prev`.
    Hop,
    /// `Extract_P(cm_old) = cmx_0`.
    Genesis,
}

impl Kind {
    /// The circuit name used in encodings and the verifying-key identifier (`WAKE-v1.md` §7.2, §7.4).
    pub fn name(self) -> &'static str {
        match self {
            Kind::Hop => "hop",
            Kind::Genesis => "genesis",
        }
    }

    /// Parse a circuit name.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "hop" => Some(Kind::Hop),
            "genesis" => Some(Kind::Genesis),
            _ => None,
        }
    }
}

/// Configuration needed to use the Wake circuits. The Action circuit's `Config`
/// minus `q_orchard`, `sinsemilla_config_2`, `commit_ivk_config` and
/// `new_note_commit_config`.
#[derive(Clone, Debug)]
pub struct Config {
    primary: Column<InstanceColumn>,
    advices: [Column<Advice>; 10],
    add_config: AddConfig,
    ecc_config: EccConfig<OrchardFixedBases>,
    poseidon_config: PoseidonConfig<pallas::Base, 3, 2>,
    merkle_config_1: MerkleConfig<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
    merkle_config_2: MerkleConfig<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
    sinsemilla_config_1:
        SinsemillaConfig<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
    old_note_commit_config: NoteCommitConfig,
}

impl Config {
    fn add_chip(&self) -> AddChip {
        AddChip::construct(self.add_config.clone())
    }

    fn ecc_chip(&self) -> EccChip<OrchardFixedBases> {
        // The fixed (NU6.2+) variable-base multiplication; the insecure one is never used.
        EccChip::construct(self.ecc_config.clone(), CircuitVersion::AnchoredBase)
    }

    fn sinsemilla_chip_1(
        &self,
    ) -> SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases> {
        SinsemillaChip::construct(self.sinsemilla_config_1.clone())
    }

    fn merkle_chip_1(
        &self,
    ) -> MerkleChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases> {
        MerkleChip::construct(self.merkle_config_1.clone())
    }

    fn merkle_chip_2(
        &self,
    ) -> MerkleChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases> {
        MerkleChip::construct(self.merkle_config_2.clone())
    }

    fn poseidon_chip(&self) -> PoseidonChip<pallas::Base, 3, 2> {
        PoseidonChip::construct(self.poseidon_config.clone())
    }

    fn note_commit_chip_old(&self) -> NoteCommitChip {
        NoteCommitChip::construct(self.old_note_commit_config.clone())
    }

    /// The Action circuit's `Config::configure` with the deletions listed in the module doc.
    fn configure(meta: &mut plonk::ConstraintSystem<pallas::Base>) -> Self {
        // Advice columns used in the Orchard circuit.
        let advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];

        // [deleted: the `q_orchard` gate; see module doc]

        // Addition of two field elements.
        let add_config = AddChip::configure(meta, advices[7], advices[8], advices[6]);

        // Fixed columns for the Sinsemilla generator lookup table
        let table_idx = meta.lookup_table_column();
        let lookup = (
            table_idx,
            meta.lookup_table_column(),
            meta.lookup_table_column(),
        );

        // Instance column used for public inputs
        let primary = meta.instance_column();
        meta.enable_equality(primary);

        // Permutation over all advice columns.
        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }

        // Poseidon requires four advice columns, while ECC incomplete addition requires
        // six, so we could choose to configure them in parallel. However, we only use a
        // single Poseidon invocation, and we have the rows to accommodate it serially.
        // Instead, we reduce the proof size by sharing fixed columns between the ECC and
        // Poseidon chips.
        let lagrange_coeffs = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let rc_a = lagrange_coeffs[2..5].try_into().unwrap();
        let rc_b = lagrange_coeffs[5..8].try_into().unwrap();

        // Also use the first Lagrange coefficient column for loading global constants.
        // It's free real estate :)
        meta.enable_constant(lagrange_coeffs[0]);

        // We have a lot of free space in the right-most advice columns; use one of them
        // for all of our range checks.
        let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);

        // Configuration for curve point operations.
        // This uses 10 advice columns and spans the whole circuit.
        let ecc_config =
            EccChip::<OrchardFixedBases>::configure(meta, advices, lagrange_coeffs, range_check);

        // Configuration for the Poseidon hash.
        let poseidon_config = PoseidonChip::configure::<poseidon::P128Pow5T3>(
            meta,
            // We place the state columns after the partial_sbox column so that the
            // pad-and-add region can be laid out more efficiently.
            advices[6..9].try_into().unwrap(),
            advices[5],
            rc_a,
            rc_b,
        );

        // Configuration for a Sinsemilla hash instantiation and a
        // Merkle hash instantiation using this Sinsemilla instance.
        // Since the Sinsemilla config uses only 5 advice columns,
        // we can fit two instances side-by-side.
        let (sinsemilla_config_1, merkle_config_1) = {
            let sinsemilla_config_1 = SinsemillaChip::configure(
                meta,
                advices[..5].try_into().unwrap(),
                advices[6],
                lagrange_coeffs[0],
                lookup,
                range_check,
                false,
            );
            let merkle_config_1 = MerkleChip::configure(meta, sinsemilla_config_1.clone());

            (sinsemilla_config_1, merkle_config_1)
        };

        // Configuration for a Sinsemilla hash instantiation and a
        // Merkle hash instantiation using this Sinsemilla instance.
        // Since the Sinsemilla config uses only 5 advice columns,
        // we can fit two instances side-by-side.
        let (sinsemilla_config_2, merkle_config_2) = {
            let sinsemilla_config_2 = SinsemillaChip::configure(
                meta,
                advices[5..].try_into().unwrap(),
                advices[7],
                lagrange_coeffs[1],
                lookup,
                range_check,
                false,
            );
            let merkle_config_2 = MerkleChip::configure(meta, sinsemilla_config_2.clone());

            (sinsemilla_config_2, merkle_config_2)
        };

        // [deleted: `commit_ivk_config`]

        // Configuration to handle decomposition and canonicity checking
        // for NoteCommit_old.
        let old_note_commit_config =
            NoteCommitChip::configure(meta, advices, sinsemilla_config_1.clone());

        // [deleted: `new_note_commit_config`. `sinsemilla_config_2` only fed it and is
        // not kept as a field; its Merkle instantiation is `merkle_config_2`.]
        let _ = sinsemilla_config_2;

        Config {
            primary,
            advices,
            add_config,
            ecc_config,
            poseidon_config,
            merkle_config_1,
            merkle_config_2,
            sinsemilla_config_1,
            old_note_commit_config,
        }
    }
}

/// One constraint a test may remove, to prove the negative test that targets it
/// is real (`zecboat_wake_circuit.md` P3: "a negative test that has never caught a
/// removed constraint is decoration"). Only exists under the `sabotage` feature.
#[cfg(feature = "sabotage")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sabotage {
    /// Drop `root = anchor`.
    RootAnchor,
    /// Drop `nf = instance[NF]`.
    Nullifier,
    /// Drop `derived cm_old = witnessed cm_old`.
    CmEquality,
    /// Drop the one Wake constraint, `LINK`.
    Link,
}

/// Constraint names, present in every build so the guards read the same.
#[derive(Clone, Copy)]
enum SabName {
    RootAnchor,
    Nullifier,
    CmEquality,
    Link,
}

#[cfg(feature = "sabotage")]
fn sab(n: SabName) -> Sabotage {
    match n {
        SabName::RootAnchor => Sabotage::RootAnchor,
        SabName::Nullifier => Sabotage::Nullifier,
        SabName::CmEquality => Sabotage::CmEquality,
        SabName::Link => Sabotage::Link,
    }
}

#[cfg(feature = "sabotage")]
impl Circuit {
    /// This circuit with one constraint removed. Test-only.
    pub fn sabotaged(mut self, s: Sabotage) -> Self {
        self.sabotage = Some(s);
        self
    }

    /// Overwrite the witnessed `rho_old` cell only, leaving `cm_old` as it was.
    /// Test-only: builds the "rho right in the instance, wrong inside the commitment" case.
    pub fn tamper_rho_old(mut self, rho: Rho) -> Self {
        self.rho_old = Value::known(rho);
        self
    }

    /// Overwrite the witnessed value only, leaving `cm_old` as it was. Test-only.
    pub fn tamper_v_old(mut self, v: NoteValue) -> Self {
        self.v_old = Value::known(v);
        self
    }
}

/// A Wake circuit: the Action circuit's spend-half witnesses plus `kind`.
///
/// `kind` is a runtime field, the way `orchard::circuit::Circuit` carries its
/// `circuit_version`: key generation with `Circuit::empty(kind)` yields a
/// distinct verifying key per kind, because the added constraint differs.
#[derive(Clone, Debug)]
pub struct Circuit {
    pub(crate) kind: Kind,
    pub(crate) path: Value<[MerkleHashOrchard; MERKLE_DEPTH_ORCHARD]>,
    pub(crate) pos: Value<u32>,
    pub(crate) g_d_old: Value<NonIdentityPallasPoint>,
    pub(crate) pk_d_old: Value<DiversifiedTransmissionKey>,
    pub(crate) v_old: Value<NoteValue>,
    pub(crate) rho_old: Value<Rho>,
    pub(crate) psi_old: Value<pallas::Base>,
    pub(crate) rcm_old: Value<NoteCommitTrapdoor>,
    pub(crate) cm_old: Value<pallas::Point>,
    pub(crate) nk: Value<NullifierDerivingKey>,
    #[cfg(feature = "sabotage")]
    pub(crate) sabotage: Option<Sabotage>,
}

impl Circuit {
    /// An empty circuit of the given kind, for key generation and layout.
    pub fn empty(kind: Kind) -> Self {
        Circuit {
            kind,
            path: Value::unknown(),
            pos: Value::unknown(),
            g_d_old: Value::unknown(),
            pk_d_old: Value::unknown(),
            v_old: Value::unknown(),
            rho_old: Value::unknown(),
            psi_old: Value::unknown(),
            rcm_old: Value::unknown(),
            cm_old: Value::unknown(),
            nk: Value::unknown(),
            #[cfg(feature = "sabotage")]
            sabotage: None,
        }
    }

    /// Build the circuit from a witness. `None` if the witness's commitment is ⊥,
    /// which cannot happen for a note that exists.
    pub fn from_witness(kind: Kind, w: &Witness) -> Option<Self> {
        let cm: Option<pallas::Point> = w.commitment().into();
        Some(Circuit {
            kind,
            path: Value::known(w.path),
            pos: Value::known(w.pos),
            g_d_old: Value::known(w.g_d),
            pk_d_old: Value::known(w.pk_d),
            v_old: Value::known(w.value),
            rho_old: Value::known(w.rho),
            psi_old: Value::known(w.psi),
            rcm_old: Value::known(w.rcm.clone()),
            cm_old: Value::known(cm?),
            nk: Value::known(w.nk),
            #[cfg(feature = "sabotage")]
            sabotage: None,
        })
    }

    /// Which relation this circuit proves.
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// Whether `s` is the constraint this instance was told to drop. Always
    /// `false` in a build without the `sabotage` feature: the match below is the
    /// only place the knob is read, and the pinned `vk_id` test shows the circuit
    /// shape is identical when it is `None`.
    #[inline]
    fn skips(&self, n: SabName) -> bool {
        #[cfg(feature = "sabotage")]
        {
            self.sabotage == Some(sab(n))
        }
        #[cfg(not(feature = "sabotage"))]
        {
            let _ = n;
            false
        }
    }

    /// The Action circuit's `synthesize_base` with the deletions listed in the
    /// module doc, one change, and one addition. Comments in brackets mark them.
    #[allow(non_snake_case)]
    fn synthesize_base(
        &self,
        config: &Config,
        layouter: &mut impl Layouter<pallas::Base>,
    ) -> Result<(), plonk::Error> {
        // Load the Sinsemilla generator lookup table used by the whole circuit.
        SinsemillaChip::load(config.sinsemilla_config_1.clone(), layouter)?;

        // Construct the ECC chip.
        let ecc_chip = config.ecc_chip();

        // Witness private inputs that are used across multiple checks.
        let (psi_old, rho_old, cm_old, g_d_old, nk, v_old) = {
            // Witness psi_old
            let psi_old = assign_free_advice(
                layouter.namespace(|| "witness psi_old"),
                config.advices[0],
                self.psi_old,
            )?;

            // Witness rho_old
            let rho_old = assign_free_advice(
                layouter.namespace(|| "witness rho_old"),
                config.advices[0],
                self.rho_old.map(|rho| rho.into_inner()),
            )?;

            // Witness cm_old
            let cm_old = Point::new(
                ecc_chip.clone(),
                layouter.namespace(|| "cm_old"),
                self.cm_old.as_ref().map(|cm| cm.to_affine()),
            )?;

            // Witness g_d_old
            let g_d_old = NonIdentityPoint::new(
                ecc_chip.clone(),
                layouter.namespace(|| "gd_old"),
                self.g_d_old.as_ref().map(|gd| gd.to_affine()),
            )?;

            // [deleted: witness ak_P]

            // Witness nk.
            let nk = assign_free_advice(
                layouter.namespace(|| "witness nk"),
                config.advices[0],
                self.nk.map(|nk| nk.inner()),
            )?;

            // Witness v_old.
            let v_old = assign_free_advice(
                layouter.namespace(|| "witness v_old"),
                config.advices[0],
                self.v_old,
            )?;

            // [deleted: witness v_new]

            (psi_old, rho_old, cm_old, g_d_old, nk, v_old)
        };

        // Merkle path validity check (https://p.z.cash/ZKS:action-merkle-path-validity?partial).
        let root = {
            let path = self
                .path
                .map(|typed_path| typed_path.map(|node| node.inner()));
            let merkle_inputs = MerklePath::construct(
                [config.merkle_chip_1(), config.merkle_chip_2()],
                OrchardHashDomains::MerkleCrh,
                self.pos,
                path,
            );
            let leaf = cm_old.extract_p().inner().clone();
            merkle_inputs.calculate_root(layouter.namespace(|| "Merkle path"), leaf)?
        };

        // [changed: the Action circuit has `v_old * (root - anchor) = 0` in the
        // `q_orchard` gate. Wake never proves a dummy; root = anchor unconditionally.]
        if !self.skips(SabName::RootAnchor) {
            layouter.constrain_instance(root.cell(), config.primary, ANCHOR)?;
        }

        // [deleted: value commitment integrity]

        // Nullifier integrity (https://p.z.cash/ZKS:action-nullifier-integrity).
        {
            let nf_old = derive_nullifier(
                layouter.namespace(|| "nf_old = DeriveNullifier_nk(rho_old, psi_old, cm_old)"),
                config.poseidon_chip(),
                config.add_chip(),
                ecc_chip.clone(),
                rho_old.clone(),
                &psi_old,
                &cm_old,
                nk,
            )?;

            // Constrain nf_old to equal public input
            if !self.skips(SabName::Nullifier) {
                layouter.constrain_instance(nf_old.inner().cell(), config.primary, NF)?;
            }
        }

        // [deleted: spend authority]

        // [deleted: diversified address integrity. pk_d_old is witnessed, not derived:
        // Wake proves nothing about the right to spend (WAKE-v1 §4.3).]
        let pk_d_old = NonIdentityPoint::new(
            ecc_chip.clone(),
            layouter.namespace(|| "witness pk_d_old"),
            self.pk_d_old.map(|pk_d_old| pk_d_old.inner().to_affine()),
        )?;

        // Old note commitment integrity (https://p.z.cash/ZKS:action-cm-old-integrity?partial).
        {
            let rcm_old = ScalarFixed::new(
                ecc_chip.clone(),
                layouter.namespace(|| "rcm_old"),
                self.rcm_old.as_ref().map(|rcm_old| rcm_old.inner()),
            )?;

            // g★_d || pk★_d || i2lebsp_{64}(v) || i2lebsp_{255}(rho) || i2lebsp_{255}(psi)
            let derived_cm_old = note_commit(
                layouter.namespace(|| {
                    "g★_d || pk★_d || i2lebsp_{64}(v) || i2lebsp_{255}(rho) || i2lebsp_{255}(psi)"
                }),
                config.sinsemilla_chip_1(),
                config.ecc_chip(),
                config.note_commit_chip_old(),
                g_d_old.inner(),
                pk_d_old.inner(),
                v_old.clone(),
                rho_old.clone(),
                psi_old,
                rcm_old,
            )?;

            // Constrain derived cm_old to equal witnessed cm_old
            if !self.skips(SabName::CmEquality) {
                derived_cm_old
                    .constrain_equal(layouter.namespace(|| "cm_old equality"), &cm_old)?;
            }
        }

        // [deleted: witness g_d_new, pk_d_new; new note commitment integrity; the
        // "Orchard circuit checks" region]

        // [added: the one Wake constraint (WAKE-v1 §5). `rho_old` is the cell that fed
        // NoteCommit and DeriveNullifier above, not a copy.]
        if !self.skips(SabName::Link) {
            match self.kind {
                Kind::Hop => layouter.constrain_instance(rho_old.cell(), config.primary, LINK)?,
                Kind::Genesis => layouter.constrain_instance(
                    cm_old.extract_p().inner().cell(),
                    config.primary,
                    LINK,
                )?,
            }
        }

        Ok(())
    }
}

impl plonk::Circuit<pallas::Base> for Circuit {
    type Config = Config;
    type FloorPlanner = floor_planner::V1;

    fn without_witnesses(&self) -> Self {
        Self::empty(self.kind)
    }

    fn configure(meta: &mut plonk::ConstraintSystem<pallas::Base>) -> Self::Config {
        Config::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), plonk::Error> {
        self.synthesize_base(&config, &mut layouter)

        // [deleted: synthesize_cross_address_checks]
    }
}
