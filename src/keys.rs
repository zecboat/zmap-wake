//! Proving and verifying keys for the two Wake circuits, and the verifying-key
//! identifier of `WAKE-v1.md` §7.4.
//!
//! Halo 2 over the Pallas/Vesta cycle needs no trusted setup: `Params::new(K)`
//! is deterministic and the keys are derived from the circuit shape alone.
//! Generation takes seconds, so both are built once per process, in a
//! `OnceLock`, with a warm-up entry point, as Zcash Coin Voting does
//! (`voting-circuits-0.12.1/src/delegation/prove.rs:30-83`).

use std::sync::OnceLock;

use halo2_proofs::{plonk, poly::commitment::Params};
use pasta_curves::vesta;

use crate::circuit::{Circuit, Kind, K};

/// The IPA parameters, shared by both circuits (same `K`).
static PARAMS: OnceLock<Params<vesta::Affine>> = OnceLock::new();
static HOP_KEYS: OnceLock<KeyPair> = OnceLock::new();
static GENESIS_KEYS: OnceLock<KeyPair> = OnceLock::new();

/// A proving key and its verifying key for one circuit kind.
#[derive(Debug)]
pub struct KeyPair {
    pub pk: plonk::ProvingKey<vesta::Affine>,
    pub vk: plonk::VerifyingKey<vesta::Affine>,
}

/// The IPA parameters for `K`.
pub fn params() -> &'static Params<vesta::Affine> {
    PARAMS.get_or_init(|| Params::new(K))
}

/// The keys for `kind`, generated on first use and cached for the process lifetime.
pub fn keys(kind: Kind) -> &'static KeyPair {
    let cell = match kind {
        Kind::Hop => &HOP_KEYS,
        Kind::Genesis => &GENESIS_KEYS,
    };
    cell.get_or_init(|| {
        let params = params();
        let circuit = Circuit::empty(kind);
        let vk = plonk::keygen_vk(params, &circuit).expect("Wake circuit is well-formed");
        let pk = plonk::keygen_pk(params, vk.clone(), &circuit).expect("Wake circuit is well-formed");
        KeyPair { pk, vk }
    })
}

/// Build every key now, off the critical path. Idempotent.
pub fn warm() {
    keys(Kind::Hop);
    keys(Kind::Genesis);
}

/// BLAKE2b personalization for the verifying-key identifier (`WAKE-v1.md` §7.4).
pub const VK_ID_PERSONALIZATION: &[u8; 10] = b"WAKE-v1-vk";
/// The `kind` string every Wake v1 encoding carries (`WAKE-v1.md` §7.2, §12).
pub const KIND_V1: &str = "wake-v1";

/// `vk_id = BLAKE2b-256(personal = "WAKE-v1-vk", input = "wake-v1" ‖ circuit_name ‖ I2BEOSP_32(k) ‖ pinned_vk)`
///
/// `pinned_vk` is the UTF-8 debug rendering of `VerifyingKey::pinned()`, the
/// stable identity of a circuit's shape. Two implementations agree on a
/// circuit if and only if their `vk_id`s agree.
pub fn vk_id(kind: Kind) -> [u8; 32] {
    let pinned = format!("{:?}", keys(kind).vk.pinned());
    let mut h = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(VK_ID_PERSONALIZATION)
        .to_state();
    h.update(KIND_V1.as_bytes());
    h.update(kind.name().as_bytes());
    h.update(&K.to_be_bytes());
    h.update(pinned.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Lower-case hex of a `vk_id`, for publishing.
pub fn vk_id_hex(kind: Kind) -> String {
    vk_id(kind).iter().map(|b| format!("{b:02x}")).collect()
}

/// Published `vk_id` of `WAKE_HOP` (`WAKE-v1.md` §7.4), first computed 2026-09-25 with
/// `halo2_proofs 0.3.2`, `halo2_gadgets 0.5.0`, `orchard 0.15.3`, `K = 11`.
pub const VK_ID_HOP: &str = "c10ee672500b17ea7c94376b6bc1ee988870b9354d1bd391ed1f1324c953707f";
/// Published `vk_id` of `WAKE_GENESIS`, same provenance.
pub const VK_ID_GENESIS: &str = "decb572630f885fd6a98266f5faea215193597eb5e83a6da8e6912bb083334e9";

#[cfg(test)]
mod tests {
    use super::*;

    /// The tripwire `WAKE-v1.md` §7.4 requires, and unlike Coin Voting's it is NOT
    /// `#[ignore]`: any drift in either circuit's shape fails `cargo test`. If a
    /// change is intentional, the version is `wake-v2` (§12), and only then do the
    /// constants above move.
    #[test]
    fn vk_ids_are_pinned() {
        assert_eq!(vk_id_hex(Kind::Hop), VK_ID_HOP, "WAKE_HOP circuit shape changed");
        assert_eq!(
            vk_id_hex(Kind::Genesis),
            VK_ID_GENESIS,
            "WAKE_GENESIS circuit shape changed"
        );
    }
}
