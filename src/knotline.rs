//! The **Knotline**: an asset's lineage kept on the chain as a line of sealed knots (the
//! owner's name for variant B of the "encrypted lineage log" design note, 2026-10-06).
//!
//! **Wire format: Knotline v1, FROZEN by the owner's decision of 2026-10-06.** Three mainnet
//! transactions of that day already carry it. Everything in "Wire forms" below, the derivation
//! of a knot's address, and the packing of a knot are pinned by the `v1_format_is_frozen` test.
//! A change to any of them is a new version: it gets a new version byte (and new tags if the
//! chunking changes), and readers keep reading v1 forever. No padding: a line that starts with
//! one proof and every later knot take the same twelve outputs.
//!
//! Each transfer ties ONE knot: its own hop. The knot is written as memos of zero-value outputs
//! to a one-time address derived from a fresh random key; the key goes to the new owner in one
//! memo of their own; and each knot carries the key and the transaction of the knot before it.
//! A new owner follows the line back from the newest knot to the first and rebuilds the lading.
//! An earlier owner never receives later keys. The public sees outputs it cannot read. There is
//! no registry and no key built into any wallet.
//!
//! Nothing here touches the circuits, the proofs or the lading's format: the rebuilt lading is
//! byte-identical to the one delivered whole, so the `consignment_hash` in the carrier's memo
//! still binds it.
//!
//! Wire forms (ZIP 302 lead byte 0xF5, "arbitrary data"). The tags and the derivation string
//! below are already on the main network (two transactions of 2026-10-06) and predate the name,
//! so they stay as they are:
//!   knot chunk    0xF5 | "WKR1" | chunk index u16 | chunk count u16 | data     (to the knot's address)
//!   key memo      0xF5 | "WKK1" | 0u16 | 1u16 | key 32                         (to the new owner)
//! Knot data: version 1 | flags (bit0 has-previous, bit1 has-genesis) | [previous key 32,
//! previous txid 32 (stored order)] | [genesis txid 32, action index u32] | hops u16 | per hop:
//! circuit 0/1, instance 3x32, anchor height u32, proof length u16, proof.

use std::collections::HashSet;

use anyhow::{anyhow, Result};
use base64::Engine;
use orchard::keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendingKey};
use orchard::note_encryption::IronwoodDomain;
use orchard::Action;
use zcash_note_encryption::try_note_decryption;

use crate::lading::{Lading, ProofEntry};
use crate::oracle::decode_hex_32;

pub const KNOT_TAG: &[u8; 4] = b"WKR1";
pub const KEY_TAG: &[u8; 4] = b"WKK1";
const HEAD: usize = 1 + 4 + 2 + 2;
const CHUNK: usize = 512 - HEAD;
const KIND_V1: &str = "wake-v1";
/// The longest walk back a reader will make.
pub const MAX_KNOTS: usize = 512;
/// A first knot (has-genesis) carries the history an item joins the line with; the reference
/// sender starts a line with at most six hops, and no honest line needs more than this.
pub const MAX_FIRST_HOPS: usize = 64;
/// The most packed-knot bytes one walk will hold (review 2026-10-09, Knotline D).
pub const MAX_WALK_BYTES: usize = 8 * 1024 * 1024; // 4096 until 2026-10-08: each knot is a server round trip (audit, Knotline B)

fn hexs(x: &[u8]) -> String {
    x.iter().map(|v| format!("{v:02x}")).collect()
}

/// The one-time address a record under `key` is written to, and the viewing key that reads it.
/// Nobody holds a spending key for it on purpose: the outputs carry no value.
pub fn knot_keys(key: &[u8; 32]) -> (FullViewingKey, orchard::Address) {
    let mut counter = 0u8;
    loop {
        let h = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"ZbWakeRecordV1__")
            .to_state()
            .update(key)
            .update(&[counter])
            .finalize();
        let seed: [u8; 32] = h.as_bytes().try_into().expect("32 bytes");
        if let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes(seed)) {
            let fvk = FullViewingKey::from(&sk);
            let addr = fvk.address_at(0u32, Scope::External);
            return (fvk, addr);
        }
        counter = counter.wrapping_add(1);
    }
}

/// One record of the log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Knot {
    /// The key and the transaction (stored byte order) of the record before this one.
    pub prev: Option<([u8; 32], [u8; 32])>,
    /// The genesis outpoint; present in the first record only.
    pub genesis: Option<(String, u32)>,
    pub hops: Vec<ProofEntry>,
}

pub fn pack_knot(r: &Knot) -> Result<Vec<u8>> {
    let mut out = vec![1u8, r.prev.is_some() as u8 | (r.genesis.is_some() as u8) << 1];
    if let Some((k, t)) = &r.prev {
        out.extend_from_slice(k);
        out.extend_from_slice(t);
    }
    if let Some((txid, idx)) = &r.genesis {
        out.extend_from_slice(&decode_hex_32(txid)?);
        out.extend_from_slice(&idx.to_le_bytes());
    }
    out.extend_from_slice(&u16::try_from(r.hops.len())?.to_le_bytes());
    for h in &r.hops {
        if h.kind != KIND_V1 {
            return Err(anyhow!("proof kind {} cannot be packed", h.kind));
        }
        out.push(match h.circuit.as_str() {
            "genesis" => 0,
            "hop" => 1,
            other => return Err(anyhow!("circuit {other} cannot be packed")),
        });
        for i in &h.instance {
            out.extend_from_slice(&decode_hex_32(i)?);
        }
        out.extend_from_slice(&h.anchor_height.to_le_bytes());
        let proof = base64::engine::general_purpose::STANDARD.decode(&h.proof)?;
        out.extend_from_slice(&u16::try_from(proof.len())?.to_le_bytes());
        out.extend_from_slice(&proof);
    }
    Ok(out)
}

pub fn unpack_knot(b: &[u8]) -> Result<Knot> {
    let mut i = 0usize;
    let mut take = |n: usize| -> Result<&[u8]> {
        let s = b.get(i..i + n).ok_or_else(|| anyhow!("knot truncated"))?;
        i += n;
        Ok(s)
    };
    if take(1)?[0] != 1 {
        return Err(anyhow!("unknown knot version"));
    }
    let flags = take(1)?[0];
    if flags & !3 != 0 {
        return Err(anyhow!("unknown knot flags"));
    }
    let prev = if flags & 1 != 0 { Some((take(32)?.try_into()?, take(32)?.try_into()?)) } else { None };
    let genesis = if flags & 2 != 0 { Some((hexs(take(32)?), u32::from_le_bytes(take(4)?.try_into()?))) } else { None };
    let n = u16::from_le_bytes(take(2)?.try_into()?) as usize;
    if n == 0 {
        return Err(anyhow!("a knot with no hop"));
    }
    let mut hops = Vec::with_capacity(n.min(64));
    for _ in 0..n {
        let circuit = match take(1)?[0] {
            0 => "genesis",
            1 => "hop",
            _ => return Err(anyhow!("unknown circuit in knot")),
        }
        .to_string();
        let instance = [hexs(take(32)?), hexs(take(32)?), hexs(take(32)?)];
        let anchor_height = u32::from_le_bytes(take(4)?.try_into()?);
        let len = u16::from_le_bytes(take(2)?.try_into()?) as usize;
        let proof = base64::engine::general_purpose::STANDARD.encode(take(len)?);
        hops.push(ProofEntry { kind: KIND_V1.to_string(), circuit, instance, anchor_height, proof });
    }
    // One encoding per knot (audit 2026-10-08, Knotline H): what follows the last hop may be
    // the zero padding of the final chunk and nothing else. A non-zero byte there is an error,
    // not ignored.
    if b[i..].iter().any(|&x| x != 0) {
        return Err(anyhow!("knot has non-zero bytes after its last hop"));
    }
    Ok(Knot { prev, genesis, hops })
}

/// Split `data` over memos under `tag`.
pub fn chunks(tag: &[u8; 4], data: &[u8]) -> Result<Vec<[u8; 512]>> {
    let total = u16::try_from(data.chunks(CHUNK).count())?;
    Ok(data
        .chunks(CHUNK)
        .enumerate()
        .map(|(i, c)| {
            let mut m = [0u8; 512];
            m[0] = 0xF5;
            m[1..5].copy_from_slice(tag);
            m[5..7].copy_from_slice(&(i as u16).to_le_bytes());
            m[7..9].copy_from_slice(&total.to_le_bytes());
            m[HEAD..HEAD + c.len()].copy_from_slice(c);
            m
        })
        .collect())
}

/// The memo that hands `key` to the new owner.
pub fn key_memo(key: &[u8; 32]) -> [u8; 512] {
    chunks(KEY_TAG, key).expect("one chunk")[0]
}

/// Reassemble what the memos carry under `tag`; `None` unless every chunk is there exactly once.
/// A memo that lost trailing zero bytes in storage is accepted.
pub fn from_memos<'a>(memos: impl IntoIterator<Item = &'a [u8]>, tag: &[u8; 4]) -> Option<Vec<u8>> {
    let mut parts: Vec<(u16, u16, Vec<u8>)> = Vec::new();
    for m in memos {
        if m.len() < HEAD || m[0] != 0xF5 || &m[1..5] != tag {
            continue;
        }
        let mut data = m[HEAD..].to_vec();
        data.resize(CHUNK, 0);
        parts.push((u16::from_le_bytes([m[5], m[6]]), u16::from_le_bytes([m[7], m[8]]), data));
    }
    parts.sort_by_key(|p| p.0);
    let total = parts.first()?.1 as usize;
    if total == 0 || parts.len() != total || parts.iter().enumerate().any(|(i, p)| p.0 as usize != i || p.1 as usize != total) {
        return None;
    }
    Some(parts.into_iter().flat_map(|p| p.2).collect())
}

/// The key a set of the owner's own memos hands over, if one is among them.
pub fn key_from_memos<'a>(memos: impl IntoIterator<Item = &'a [u8]>) -> Option<[u8; 32]> {
    from_memos(memos, KEY_TAG)?.get(..32)?.try_into().ok()
}

/// The record that `key` opens among these actions, if any.
pub fn read_knot<T>(actions: &[Action<T>], key: &[u8; 32]) -> Option<Vec<u8>> {
    let (fvk, _) = knot_keys(key);
    let ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));
    let memos: Vec<[u8; 512]> = actions
        .iter()
        .filter_map(|a| try_note_decryption(&IronwoodDomain::for_action(a), &ivk, a).map(|(_, _, memo)| memo))
        .collect();
    from_memos(memos.iter().map(|m| &m[..]), KNOT_TAG)
}

/// The record that `key` opens in a raw transaction mined at `height`.
pub fn read_knot_in_tx(raw: &[u8], height: u32, network: &zcash_protocol::consensus::Network, key: &[u8; 32]) -> Result<Option<Vec<u8>>> {
    use zcash_primitives::transaction::Transaction;
    use zcash_protocol::consensus::{BlockHeight, BranchId};
    let branch = BranchId::for_height(network, BlockHeight::from_u32(height));
    let tx = Transaction::read(raw, branch).map_err(|e| anyhow!("cannot parse the transaction: {e}"))?;
    Ok(tx.ironwood_bundle().and_then(|b| {
        let actions: Vec<_> = b.actions().iter().cloned().collect();
        read_knot(&actions, key)
    }))
}

/// Walk back from the knot that `key` opens in transaction `txid` to the first knot, and
/// rebuild the lading. `open(key, txid, height)` returns the packed knot that `key` opens in
/// that transaction, or `None`. `height` is the block the transaction is mined in when the
/// walk knows it: a knot's proof is anchored at the block its note was mined in, which is the
/// block of the previous knot's transaction. A reader can use it to fetch that transaction
/// without telling a server which one it wants.
pub fn walk_back(
    mut key: [u8; 32],
    mut txid: [u8; 32],
    open: &mut dyn FnMut(&[u8; 32], &[u8; 32], Option<u32>) -> Result<Option<Vec<u8>>>,
) -> Result<(Lading, usize)> {
    let mut height: Option<u32> = None;
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut groups: Vec<Vec<ProofEntry>> = Vec::new();
    let mut total_bytes = 0usize;
    let genesis = loop {
        if !seen.insert(txid) || seen.len() > MAX_KNOTS {
            return Err(anyhow!("the Knotline loops or is longer than {MAX_KNOTS} knots"));
        }
        let bytes = open(&key, &txid, height)?.ok_or_else(|| anyhow!("no knot opens with the key in hand in transaction {}…", hexs(&txid[..6])))?;
        // Bounds on what a line can make a reader hold (review 2026-10-09, Knotline D): a
        // later knot carries exactly its own hop, a first knot at most MAX_FIRST_HOPS, and the
        // whole walk at most MAX_WALK_BYTES of packed knots.
        total_bytes += bytes.len();
        if total_bytes > MAX_WALK_BYTES {
            return Err(anyhow!("the Knotline is larger than {MAX_WALK_BYTES} bytes; refused"));
        }
        let r = unpack_knot(&bytes)?;
        if r.prev.is_some() && r.hops.len() != 1 {
            return Err(anyhow!("a later knot carries {} hops; exactly one is allowed", r.hops.len()));
        }
        if r.genesis.is_some() && r.hops.len() > MAX_FIRST_HOPS {
            return Err(anyhow!("the first knot carries {} hops; at most {MAX_FIRST_HOPS} are allowed", r.hops.len()));
        }
        groups.push(r.hops);
        match r.prev {
            Some((k, t)) => {
                if r.genesis.is_some() {
                    return Err(anyhow!("a knot names both a predecessor and a genesis"));
                }
                key = k;
                txid = t;
                height = groups.last().and_then(|g| g.first()).map(|h| h.anchor_height);
            }
            None => break r.genesis.ok_or_else(|| anyhow!("the first knot names no genesis"))?,
        }
    };
    let fetched = groups.len();
    let mut lading = Lading::new(&genesis.0, genesis.1);
    for g in groups.into_iter().rev() {
        lading.hops.extend(g);
    }
    Ok((lading, fetched))
}

#[cfg(test)]
mod tests {
    /// A line the reader must refuse: a later knot with two hops, and one knot past the bound
    /// (review 2026-10-09, Knotline D and H).
    #[test]
    fn walks_are_bounded_in_hops_per_knot_and_in_knots() {
        use super::*;
        use base64::Engine;
        let hop = |n: u32| ProofEntry {
            kind: super::super::keys::KIND_V1.to_string(),
            circuit: if n == 0 { "genesis".into() } else { "hop".into() },
            instance: [format!("{:064x}", n + 1), format!("{:064x}", n + 2), format!("{:064x}", n + 3)],
            anchor_height: 1,
            proof: base64::engine::general_purpose::STANDARD.encode(vec![7u8; 8]),
        };
        // A two-hop later knot.
        let bad = pack_knot(&Knot { prev: Some(([1u8; 32], [2u8; 32])), genesis: None, hops: vec![hop(1), hop(2)] }).unwrap();
        let mut open_bad = |_: &[u8; 32], _: &[u8; 32], _: Option<u32>| Ok(Some(bad.clone()));
        let err = walk_back([9u8; 32], [8u8; 32], &mut open_bad).unwrap_err().to_string();
        assert!(err.contains("exactly one"), "{err}");
        // MAX_KNOTS + 1 minimal knots in a chain: txid i links to i - 1; refused before the end.
        let n = MAX_KNOTS + 1;
        let knot_at = |i: usize| -> Vec<u8> {
            let mut t = [0u8; 32];
            t[..8].copy_from_slice(&(i as u64).to_le_bytes());
            if i == 0 {
                pack_knot(&Knot { prev: None, genesis: Some(("ab".repeat(32), 0)), hops: vec![hop(0)] }).unwrap()
            } else {
                let mut p = [0u8; 32];
                p[..8].copy_from_slice(&((i - 1) as u64).to_le_bytes());
                pack_knot(&Knot { prev: Some(([3u8; 32], p)), genesis: None, hops: vec![hop(i as u32)] }).unwrap()
            }
        };
        let mut open_long = |_: &[u8; 32], txid: &[u8; 32], _: Option<u32>| {
            let i = u64::from_le_bytes(txid[..8].try_into().unwrap()) as usize;
            Ok(Some(knot_at(i)))
        };
        let mut top = [0u8; 32];
        top[..8].copy_from_slice(&((n - 1) as u64).to_le_bytes());
        let err = walk_back([3u8; 32], top, &mut open_long).unwrap_err().to_string();
        assert!(err.contains("longer than"), "{err}");
    }

    #[test]
    fn trailing_bytes_after_a_knot_are_refused() {
        let k = super::Knot {
            prev: None,
            genesis: Some(("ab".repeat(32), 3)),
            hops: vec![super::ProofEntry { kind: super::KIND_V1.into(), circuit: "genesis".into(), instance: ["00".repeat(32), "11".repeat(32), "22".repeat(32)], anchor_height: 7, proof: String::new() }],
        };
        let packed = super::pack_knot(&k).unwrap();
        assert!(super::unpack_knot(&packed).is_ok());
        let mut padded = packed.clone();
        padded.extend_from_slice(&[0u8; 17]);
        assert!(super::unpack_knot(&padded).is_ok(), "chunk padding is zeros");
        let mut longer = packed.clone();
        longer.extend_from_slice(&[0, 0, 1]);
        assert!(super::unpack_knot(&longer).is_err(), "a non-zero byte after the last hop");
    }

    use super::*;
    use orchard::builder::{Builder, BundleType};
    use orchard::bundle::BundleVersion;
    use orchard::value::NoteValue;
    use rand::rngs::OsRng;
    use std::collections::HashMap;

    fn hop(j: usize) -> ProofEntry {
        ProofEntry {
            kind: KIND_V1.to_string(),
            circuit: if j == 0 { "genesis" } else { "hop" }.to_string(),
            instance: [format!("{:064x}", j + 1), format!("{:064x}", j + 2), format!("{:064x}", j + 3)],
            anchor_height: 3_500_000 + j as u32,
            proof: base64::engine::general_purpose::STANDARD.encode(vec![j as u8 + 1; 4960]),
        }
    }

    /// Unproven actions carrying a key memo to `owner` and a record under `key`.
    fn actions(owner: orchard::Address, key: &[u8; 32], record: &[u8]) -> Vec<Action<()>> {
        let v = BundleVersion::ironwood_v3();
        let mut b = Builder::new(BundleType::DEFAULT, v, v.default_flags(), orchard::tree::Anchor::empty_tree()).unwrap();
        b.add_output(None, owner, NoteValue::from_raw(0), key_memo(key)).unwrap();
        let (_, to) = knot_keys(key);
        for m in chunks(KNOT_TAG, record).unwrap() {
            b.add_output(None, to, NoteValue::from_raw(0), m).unwrap();
        }
        let (bundle, _) = b.build::<i64>(OsRng).unwrap().unwrap();
        bundle.actions().iter().map(|a| a.clone().map(|_| ())).collect()
    }

    /// Knotline v1 is frozen. If this test fails, the change being made breaks every knot
    /// already on the chain: do not edit the expected values, add a new version instead.
    #[test]
    fn v1_format_is_frozen() {
        use sha2::{Digest, Sha256};
        let hx = |b: &[u8]| b.iter().map(|v| format!("{v:02x}")).collect::<String>();
        assert_eq!((KNOT_TAG, KEY_TAG, HEAD, CHUNK), (b"WKR1", b"WKK1", 9, 503));

        // A knot's address is a fixed function of its key.
        let (_, addr) = knot_keys(&[0x11; 32]);
        assert_eq!(hx(&addr.to_raw_address_bytes()), "35c679162ac1cf05fe3a21d14b48a0f6617bd35ed509e6b685df34acc6edd70fb9f26b9a8e3eff4ada4abf");

        // Packing: a later knot (previous key and transaction, one hop) and a first knot.
        let h = ProofEntry {
            kind: KIND_V1.to_string(),
            circuit: "hop".to_string(),
            instance: ["01".repeat(32), "02".repeat(32), "03".repeat(32)],
            anchor_height: 3_508_581,
            proof: base64::engine::general_purpose::STANDARD.encode(vec![7u8; 4960]),
        };
        let later = pack_knot(&Knot { prev: Some(([0x22; 32], [0x33; 32])), genesis: None, hops: vec![h.clone()] }).unwrap();
        let first = pack_knot(&Knot { prev: None, genesis: Some(("ab".repeat(32), 3)), hops: vec![ProofEntry { circuit: "genesis".to_string(), ..h.clone() }] }).unwrap();
        assert_eq!((later.len(), hx(&Sha256::digest(&later)).as_str()), (5131, "1e949f7508ddfaba4f351b07bf4a48c2aa86bcdbc3b61ac03f88670c65dc81eb"));
        assert_eq!((first.len(), hx(&Sha256::digest(&first)).as_str()), (5103, "dcf4b5e68906d40b45493134c3c00cf8c14c93cd9c69402de0a3c061463bf3fd"));
        assert_eq!(&later[..2], &[1, 1], "version 1, flags: has-previous");
        assert_eq!(&first[..2], &[1, 2], "version 1, flags: has-genesis");

        // The lading's canonical bytes. A reader rebuilds the lading from knots and its hash
        // must equal the one the sender put in the carrier's memo, so both must serialise the
        // same structure to the same bytes: JSON as `Lading::to_bytes` writes it (two-space
        // indentation, keys in declaration order, no trailing newline). If a dependency ever
        // changes that output, this fails before any wallet ships with it.
        let mut l = Lading::new(&"ab".repeat(32), 3);
        l.hops.push(ProofEntry { circuit: "genesis".to_string(), ..h.clone() });
        l.hops.push(h.clone());
        let bytes = l.to_bytes();
        assert!(bytes.starts_with(b"{\n  \"wake_lading\": 1,\n  \"genesis\": {\n    \"txid\": \"abab"));
        assert!(bytes.ends_with(b"\"\n    }\n  ]\n}"));
        assert_eq!((bytes.len(), hx(&Sha256::digest(&bytes)).as_str()), (14132, "66c4b7ab20cf0525b062b8ae9c80828f5e818c54c1d98c62af2e82e4fe3c9472"));
        assert_eq!(Lading::parse(&bytes).unwrap().to_bytes(), bytes, "parse then serialise is the identity");

        // Chunking: eleven memos either way, plus the key memo: twelve outputs, no padding.
        let memos = chunks(KNOT_TAG, &later).unwrap();
        assert_eq!((memos.len(), chunks(KNOT_TAG, &first).unwrap().len()), (11, 11));
        assert_eq!(&memos[0][..9], &[0xF5, b'W', b'K', b'R', b'1', 0, 0, 11, 0]);
        assert_eq!(&memos[10][..9], &[0xF5, b'W', b'K', b'R', b'1', 10, 0, 11, 0]);
        let km = key_memo(&[0x44; 32]);
        assert_eq!(&km[..9], &[0xF5, b'W', b'K', b'K', b'1', 0, 0, 1, 0]);
        assert_eq!(&km[9..41], &[0x44; 32]);
        assert!(km[41..].iter().all(|b| *b == 0));
    }

    #[test]
    fn records_pack_losslessly() {
        let first = Knot { prev: None, genesis: Some(("ab".repeat(32), 7)), hops: vec![hop(0), hop(1)] };
        let later = Knot { prev: Some(([9u8; 32], [8u8; 32])), genesis: None, hops: vec![hop(2)] };
        for r in [first, later] {
            assert_eq!(unpack_knot(&pack_knot(&r).unwrap()).unwrap(), r);
        }
        assert_eq!(chunks(KNOT_TAG, &pack_knot(&Knot { prev: Some(([1; 32], [2; 32])), genesis: None, hops: vec![hop(3)] }).unwrap()).unwrap().len(), 11);
        assert!(unpack_knot(&[1, 0, 0, 0]).is_err(), "no hop");
        assert!(unpack_knot(&[2]).is_err(), "version");
    }

    #[test]
    fn a_new_owner_walks_back_and_an_old_key_reads_nothing_newer() {
        let owner = knot_keys(&[42u8; 32]).1; // any address will do as the owner's
        let keys = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let ids = [[11u8; 32], [12u8; 32], [13u8; 32]];
        let mut chain: HashMap<[u8; 32], Vec<Action<()>>> = HashMap::new();
        let want = {
            let mut l = Lading::new(&"ab".repeat(32), 7);
            l.hops = vec![hop(0), hop(1), hop(2)];
            l
        };
        for j in 0..3 {
            let r = Knot {
                prev: (j > 0).then(|| (keys[j - 1], ids[j - 1])),
                genesis: (j == 0).then(|| ("ab".repeat(32), 7)),
                hops: vec![hop(j)],
            };
            chain.insert(ids[j], actions(owner, &keys[j], &pack_knot(&r).unwrap()));
        }
        let mut open = |k: &[u8; 32], t: &[u8; 32], _h: Option<u32>| Ok(chain.get(t).and_then(|a| read_knot(a, k)));
        let (got, fetched) = walk_back(keys[2], ids[2], &mut open).unwrap();
        assert_eq!(fetched, 3);
        assert_eq!(got.to_bytes(), want.to_bytes(), "byte-identical to the lading delivered whole");

        // The key of record 2 opens record 2 and what came before, never record 3.
        assert!(read_knot(&chain[&ids[2]], &keys[1]).is_none());
        let (older, _) = walk_back(keys[1], ids[1], &mut open).unwrap();
        assert_eq!(older.hops.len(), 2);
        // A wrong key, a missing transaction and a loop are errors, not partial ladings.
        assert!(walk_back([7u8; 32], ids[2], &mut open).is_err());
        assert!(walk_back(keys[2], [99u8; 32], &mut open).is_err());
        let looped = Knot { prev: Some((keys[0], ids[0])), genesis: None, hops: vec![hop(1)] };
        chain.insert(ids[0], actions(owner, &keys[0], &pack_knot(&looped).unwrap()));
        let mut open = |k: &[u8; 32], t: &[u8; 32], _h: Option<u32>| Ok(chain.get(t).and_then(|a| read_knot(a, k)));
        assert!(walk_back(keys[0], ids[0], &mut open).unwrap_err().to_string().contains("loops"));
    }

    #[test]
    fn the_key_memo_is_found_among_other_memos_and_trimmed_storage() {
        let k = [5u8; 32];
        let mut stored = key_memo(&k).to_vec();
        while stored.last() == Some(&0) {
            stored.pop();
        }
        let others: Vec<Vec<u8>> = vec![vec![0xF6], br#"{"asset_id":"x"}"#.to_vec(), stored];
        assert_eq!(key_from_memos(others.iter().map(|m| m.as_slice())), Some(k));
        assert_eq!(key_from_memos([&[0xF6u8][..]]), None);
    }
}
