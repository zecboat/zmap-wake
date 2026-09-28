//! Sealing a lading to a recipient's Orchard/Ironwood address (chapter 8 delivery).
//!
//! `ZMAP-v0.5.md` §15: a consignment is delivered off-chain, *encrypted to the recipient*,
//! and never served in plaintext or by listing. The recipient is known to the sender only as
//! a unified address, so the key agreement is the one Zcash already performs for every
//! shielded output: an ephemeral secret against the address's diversified transmission key,
//! through the Ironwood note-encryption domain (`orchard::note_encryption`). The recipient
//! opens it with the incoming viewing key their wallet already holds. No extra key exchange,
//! no key server.
//!
//! The symmetric layer is ChaCha20-Poly1305 under a key derived from the domain's KDF output
//! with a Wake-specific BLAKE2b personalisation, so a sealed lading can never be confused with
//! a note ciphertext even if the same ephemeral key were reused.
//!
//! What this does not do: authenticate the sender. The lading's proofs are self-authenticating
//! against the chain; who delivered them is not something the recipient needs to know.

use anyhow::{anyhow, Result};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ff::{Field, PrimeField};
use orchard::keys::{FullViewingKey, PreparedIncomingViewingKey, Scope};
use orchard::note::{Note, NoteVersion, RandomSeed, Rho};
use orchard::note_encryption::IronwoodDomain;
use orchard::value::NoteValue;
use orchard::Address;
use pasta_curves::pallas;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zcash_note_encryption::{Domain, EphemeralKeyBytes};

use crate::oracle::{decode_hex_32, hex};

/// Format version of [`Sealed`].
pub const SEALED_VERSION: u32 = 1;

/// BLAKE2b personalisation for the symmetric key. Exactly 16 bytes.
const KEY_PERSONAL: &[u8; 16] = b"WAKE-seal-v1-key";

/// A lading encrypted to one address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    pub wake_sealed: u32,
    /// Ephemeral public key, 32 bytes, lower-case hex.
    pub epk: String,
    /// 12-byte nonce, hex.
    pub nonce: String,
    /// ChaCha20-Poly1305 ciphertext with tag, standard base64.
    pub ciphertext: String,
}

impl Sealed {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("sealed lading serialises")
    }

    pub fn parse(bytes: &[u8]) -> Result<Sealed> {
        let s: Sealed = serde_json::from_slice(bytes).map_err(|e| anyhow!("sealed lading is not valid JSON: {e}"))?;
        if s.wake_sealed != SEALED_VERSION {
            return Err(anyhow!("unsupported wake_sealed version {}", s.wake_sealed));
        }
        Ok(s)
    }
}

fn symmetric_key(kdf_out: blake2b_simd::Hash) -> [u8; 32] {
    let h = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(KEY_PERSONAL)
        .hash(kdf_out.as_bytes());
    let mut k = [0u8; 32];
    k.copy_from_slice(h.as_bytes());
    k
}

/// Seal `plaintext` to `recipient`.
pub fn seal(recipient: &Address, plaintext: &[u8], rng: &mut impl RngCore) -> Result<Sealed> {
    // A throwaway note carrying the recipient's address is the vehicle for the domain's
    // key agreement; its value, rho and rseed are irrelevant and never leave this function.
    let rho_f = pallas::Base::random(&mut *rng);
    let rho = Option::<Rho>::from(Rho::from_bytes(&rho_f.to_repr()))
        .ok_or_else(|| anyhow!("internal: random rho not canonical"))?;
    // `RandomSeed::random` is crate-private in orchard; `from_bytes` is the public door and
    // rejects only seeds whose derived esk would be zero, so the loop ends at once in practice.
    let rseed = loop {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        if let Some(r) = Option::<RandomSeed>::from(RandomSeed::from_bytes(b, &rho)) {
            break r;
        }
    };
    let note = Option::<Note>::from(Note::from_parts(
        *recipient,
        NoteValue::from_raw(0),
        rho,
        rseed,
        NoteVersion::V3,
    ))
    .ok_or_else(|| anyhow!("internal: could not form a note for the recipient address"))?;

    let esk = <IronwoodDomain as Domain>::derive_esk(&note)
        .ok_or_else(|| anyhow!("internal: no ephemeral secret for the note"))?;
    let epk = <IronwoodDomain as Domain>::ka_derive_public(&note, &esk);
    let pk_d = <IronwoodDomain as Domain>::get_pk_d(&note);
    let shared = <IronwoodDomain as Domain>::ka_agree_enc(&esk, &pk_d);
    let epk_bytes = <IronwoodDomain as Domain>::epk_bytes(&epk);
    let key = symmetric_key(<IronwoodDomain as Domain>::kdf(shared, &epk_bytes));

    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| anyhow!("encryption failed"))?;
    Ok(Sealed {
        wake_sealed: SEALED_VERSION,
        epk: hex(&epk_bytes.0),
        nonce: hex(&nonce),
        ciphertext: base64::engine::general_purpose::STANDARD.encode(ct),
    })
}

/// Open a sealed lading with the recipient's full viewing key. Both scopes are tried,
/// since a carrier may have been sent to an internal (change) address.
pub fn open(fvk: &FullViewingKey, sealed: &Sealed) -> Result<Vec<u8>> {
    let epk_raw = decode_hex_32(&sealed.epk)?;
    let nonce_raw = hex_bytes(&sealed.nonce)?;
    if nonce_raw.len() != 12 {
        return Err(anyhow!("nonce is not 12 bytes"));
    }
    let ct = base64::engine::general_purpose::STANDARD
        .decode(&sealed.ciphertext)
        .map_err(|_| anyhow!("ciphertext is not valid base64"))?;
    let epk_bytes = EphemeralKeyBytes(epk_raw);
    for scope in [Scope::External, Scope::Internal] {
        let ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(scope));
        let epk = <IronwoodDomain as Domain>::epk(&epk_bytes)
            .ok_or_else(|| anyhow!("ephemeral key is not a valid point"))?;
        let prepared = <IronwoodDomain as Domain>::prepare_epk(epk);
        let shared = <IronwoodDomain as Domain>::ka_agree_dec(&ivk, &prepared);
        let key = symmetric_key(<IronwoodDomain as Domain>::kdf(shared, &epk_bytes));
        let cipher = ChaCha20Poly1305::new((&key).into());
        if let Ok(pt) = cipher.decrypt(Nonce::from_slice(&nonce_raw), ct.as_slice()) {
            return Ok(pt);
        }
    }
    Err(anyhow!("this wallet's keys do not open the sealed lading"))
}

fn hex_bytes(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(anyhow!("odd-length hex"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow!("bad hex: {e}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn keys() -> (FullViewingKey, Address) {
        let (_sk, fvk, note) = Note::dummy(&mut OsRng, None, NoteVersion::V3);
        (fvk, note.recipient())
    }

    #[test]
    fn round_trip_external_scope() {
        let (fvk, addr) = keys();
        let msg = b"{\"wake_lading\":1}";
        let sealed = seal(&addr, msg, &mut OsRng).unwrap();
        let back = open(&fvk, &Sealed::parse(&sealed.to_bytes()).unwrap()).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn round_trip_internal_scope() {
        let (_sk, fvk, _n) = Note::dummy(&mut OsRng, None, NoteVersion::V3);
        let addr = fvk.address_at(0u32, Scope::Internal);
        let msg = b"internal";
        let sealed = seal(&addr, msg, &mut OsRng).unwrap();
        assert_eq!(open(&fvk, &sealed).unwrap(), msg);
    }

    #[test]
    fn wrong_key_does_not_open() {
        let (_fvk, addr) = keys();
        let (other, _) = keys();
        let sealed = seal(&addr, b"secret", &mut OsRng).unwrap();
        assert!(open(&other, &sealed).is_err());
    }

    #[test]
    fn tampered_ciphertext_does_not_open() {
        let (fvk, addr) = keys();
        let mut sealed = seal(&addr, b"secret", &mut OsRng).unwrap();
        let mut ct = base64::engine::general_purpose::STANDARD.decode(&sealed.ciphertext).unwrap();
        ct[0] ^= 1;
        sealed.ciphertext = base64::engine::general_purpose::STANDARD.encode(ct);
        assert!(open(&fvk, &sealed).is_err());
    }

    #[test]
    fn two_seals_of_one_message_differ() {
        let (_fvk, addr) = keys();
        let a = seal(&addr, b"x", &mut OsRng).unwrap();
        let b = seal(&addr, b"x", &mut OsRng).unwrap();
        assert_ne!(a.epk, b.epk);
        assert_ne!(a.ciphertext, b.ciphertext);
    }
}
