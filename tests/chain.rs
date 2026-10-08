//! Chapter 6: a 3-hop synthetic chain verifies end to end, and every
//! `WakeFailure` variant is produced by exactly one mutation of a good lading.
//!
//! The oracle is a mock: it knows the three fixture anchors at three heights and
//! the genesis output's cmx. Real oracles are exercised in chapter 7.

use std::cell::Cell;
use std::collections::HashMap;

use base64::Engine;
use ff::{Field, PrimeField};
use orchard::note::{ExtractedNoteCommitment, NoteVersion, Rho};
use orchard::tree::Anchor;
use pasta_curves::pallas;
use rand::rngs::OsRng;
use zmap_wake::lading::{lading_hash, Lading, ProofEntry};
use zmap_wake::oracle::{hex, AnchorStatus, ChainOracle, OracleTrust, MIN_DEPTH};
use zmap_wake::prove::{prove_genesis, prove_hop};
use zmap_wake::testing::{fixture, Fixture};
use zmap_wake::verify::{verify_chain, WakeFailure};

struct MockOracle {
    tip: u32,
    anchors: HashMap<[u8; 32], u32>,
    outputs: HashMap<([u8; 32], u32), ExtractedNoteCommitment>,
    calls: Cell<usize>,
}

impl ChainOracle for MockOracle {
    fn trust(&self) -> OracleTrust {
        OracleTrust::FullNode
    }
    fn anchor_at(&self, root: &Anchor, height: u32) -> anyhow::Result<AnchorStatus> {
        self.calls.set(self.calls.get() + 1);
        Ok(match self.anchors.get(&root.to_bytes()) {
            Some(&h) if h == height && h <= self.tip => AnchorStatus::Known {
                depth: self.tip - h,
            },
            _ => AnchorStatus::Unknown,
        })
    }
    fn cmx_at(&self, txid: &[u8; 32], idx: u32) -> anyhow::Result<Option<ExtractedNoteCommitment>> {
        self.calls.set(self.calls.get() + 1);
        Ok(self.outputs.get(&(*txid, idx)).copied())
    }
}

struct Chain {
    n: [Fixture; 3],
    note_in_hand_rho: Rho,
    genesis_txid: [u8; 32],
    lading: Lading,
    bytes: Vec<u8>,
    oracle: MockOracle,
}

const HEIGHTS: [u32; 3] = [1_000, 2_000, 3_000];
const TIP: u32 = 5_000;

fn build_chain() -> Chain {
    let n0 = fixture(NoteVersion::V3, 10_000, None);
    let n1 = fixture(
        NoteVersion::V3,
        10_000,
        Some(Rho::from_nf_old(n0.note.nullifier(&n0.fvk))),
    );
    let n2 = fixture(
        NoteVersion::V3,
        10_000,
        Some(Rho::from_nf_old(n1.note.nullifier(&n1.fvk))),
    );
    let note_in_hand_rho = Rho::from_nf_old(n2.note.nullifier(&n2.fvk));
    let genesis_txid = [0x11u8; 32];

    let mut lading = Lading::new(&hex(&genesis_txid), 0);
    lading.hops.push(ProofEntry::from_proof(&prove_genesis(&n0.witness).unwrap(), HEIGHTS[0]));
    lading.hops.push(ProofEntry::from_proof(&prove_hop(&n1.witness).unwrap(), HEIGHTS[1]));
    lading.hops.push(ProofEntry::from_proof(&prove_hop(&n2.witness).unwrap(), HEIGHTS[2]));
    let bytes = lading.to_bytes();

    let n = [n0, n1, n2];
    let mut anchors = HashMap::new();
    for (f, h) in n.iter().zip(HEIGHTS) {
        anchors.insert(f.anchor.to_bytes(), h);
    }
    let mut outputs = HashMap::new();
    outputs.insert(
        (genesis_txid, 0),
        ExtractedNoteCommitment::from(n[0].note.commitment()),
    );
    let oracle = MockOracle {
        tip: TIP,
        anchors,
        outputs,
        calls: Cell::new(0),
    };
    Chain {
        n,
        note_in_hand_rho,
        genesis_txid,
        lading,
        bytes,
        oracle,
    }
}

fn run(c: &Chain, bytes: &[u8], hash: Option<[u8; 32]>) -> Result<zmap_wake::Verified, WakeFailure> {
    verify_chain(bytes, hash, &c.note_in_hand_rho, &c.oracle, MIN_DEPTH)
}

#[test]
fn three_hop_chain_verifies_and_each_failure_has_one_cause() {
    let mut c = build_chain();
    let good_hash = lading_hash(&c.bytes);

    // The good case, with and without the memo hash.
    let v = run(&c, &c.bytes, Some(good_hash)).expect("chain verifies");
    assert_eq!(v.hops, 3);
    assert_eq!(v.final_nf, c.note_in_hand_rho.to_bytes());
    assert_eq!(v.min_anchor_depth, TIP - HEIGHTS[2]);
    assert_eq!(v.trust, OracleTrust::FullNode);
    assert_eq!(
        v.genesis_cmx,
        ExtractedNoteCommitment::from(c.n[0].note.commitment()).to_bytes()
    );
    run(&c, &c.bytes, None).expect("chain verifies without a memo hash");
    // No nullifier-set lookups: exactly one cmx query and three anchor queries.
    assert_eq!(c.oracle.calls.get(), 2 * 4);

    // 1. LadingHashMismatch: a single byte of whitespace changes the delivered bytes.
    let mut padded = c.bytes.clone();
    padded.push(b'\n');
    assert_eq!(run(&c, &padded, Some(good_hash)), Err(WakeFailure::LadingHashMismatch));
    // Without a hash the padded bytes are refused too: only the canonical encoding is a lading.
    assert!(matches!(run(&c, &padded, None), Err(WakeFailure::Malformed(_))));

    // 2. GenesisNotOnChain: the oracle has a different cmx at the genesis output.
    let other = fixture(NoteVersion::V3, 10_000, None);
    let real = c.oracle.outputs.insert(
        (c.genesis_txid, 0),
        ExtractedNoteCommitment::from(other.note.commitment()),
    );
    assert_eq!(run(&c, &c.bytes, None), Err(WakeFailure::GenesisNotOnChain));
    c.oracle.outputs.insert((c.genesis_txid, 0), real.unwrap());
    // ... or the lading names an output the oracle does not know.
    let mut l = c.lading.clone();
    l.genesis.action_index = 7;
    assert_eq!(run(&c, &l.to_bytes(), None), Err(WakeFailure::GenesisNotOnChain));

    // 3. AnchorUnknown(1): the oracle has never seen hop 1's root.
    let h1 = c.oracle.anchors.remove(&c.n[1].anchor.to_bytes()).unwrap();
    assert_eq!(run(&c, &c.bytes, None), Err(WakeFailure::AnchorUnknown(1)));
    c.oracle.anchors.insert(c.n[1].anchor.to_bytes(), h1);
    // ... or the lading claims the wrong height for a real root.
    let mut l = c.lading.clone();
    l.hops[1].anchor_height += 1;
    assert_eq!(run(&c, &l.to_bytes(), None), Err(WakeFailure::AnchorUnknown(1)));

    // 4. AnchorTooShallow: hop 2's block is 50 below the tip.
    c.oracle.anchors.insert(c.n[2].anchor.to_bytes(), TIP - 50);
    let mut l = c.lading.clone();
    l.hops[2].anchor_height = TIP - 50;
    assert_eq!(
        run(&c, &l.to_bytes(), None),
        Err(WakeFailure::AnchorTooShallow { hop: 2, depth: 50 })
    );
    c.oracle.anchors.insert(c.n[2].anchor.to_bytes(), HEIGHTS[2]);

    // 5. BadProof(1): one byte of hop 1's transcript flipped.
    let mut l = c.lading.clone();
    let mut proof = base64::engine::general_purpose::STANDARD
        .decode(&l.hops[1].proof)
        .unwrap();
    proof[100] ^= 0x01;
    l.hops[1].proof = base64::engine::general_purpose::STANDARD.encode(&proof);
    assert_eq!(run(&c, &l.to_bytes(), None), Err(WakeFailure::BadProof(1)));

    // 6. ChainBreak(2): hop 2 replaced by a valid proof of an unrelated note.
    let stranger = fixture(NoteVersion::V3, 10_000, None);
    c.oracle.anchors.insert(stranger.anchor.to_bytes(), HEIGHTS[2]);
    let mut l = c.lading.clone();
    l.hops[2] = ProofEntry::from_proof(&prove_hop(&stranger.witness).unwrap(), HEIGHTS[2]);
    assert_eq!(run(&c, &l.to_bytes(), None), Err(WakeFailure::ChainBreak(2)));

    // 7. RhoMismatch: the note in hand is not the successor of hop 2.
    let wrong_rho = Rho::from_bytes(&pallas::Base::random(&mut OsRng).to_repr()).unwrap();
    assert_eq!(
        verify_chain(&c.bytes, None, &wrong_rho, &c.oracle, MIN_DEPTH),
        Err(WakeFailure::RhoMismatch)
    );

    // 8. UnsupportedProofKind: a future kind is rejected, never guessed.
    let mut l = c.lading.clone();
    l.hops[1].kind = "wake-v2".into();
    assert_eq!(
        run(&c, &l.to_bytes(), None),
        Err(WakeFailure::UnsupportedProofKind("wake-v2".into()))
    );

    // 9. Malformed: hops[0] is not a genesis proof; a hop in position 0.
    let mut l = c.lading.clone();
    l.hops[0].circuit = "hop".into();
    assert!(matches!(run(&c, &l.to_bytes(), None), Err(WakeFailure::Malformed(_))));
    // ... an empty lading; a non-JSON lading; a wrong version.
    let mut l = c.lading.clone();
    l.hops.clear();
    assert!(matches!(run(&c, &l.to_bytes(), None), Err(WakeFailure::Malformed(_))));
    assert!(matches!(run(&c, b"not json", None), Err(WakeFailure::Malformed(_))));
    let mut l = c.lading.clone();
    l.wake_lading = 2;
    assert!(matches!(run(&c, &l.to_bytes(), None), Err(WakeFailure::Malformed(_))));

    // The good lading still verifies after all of the above: mutations were on copies.
    run(&c, &c.bytes, Some(good_hash)).expect("still verifies");
}

/// A server-asserted oracle verifies the chain but the verdict carries `ServerAsserted`.
#[test]
fn light_client_verdict_is_server_asserted() {
    struct Relay<'a>(&'a MockOracle);
    impl ChainOracle for Relay<'_> {
        fn anchor_at(&self, r: &Anchor, h: u32) -> anyhow::Result<AnchorStatus> {
            self.0.anchor_at(r, h)
        }
        fn cmx_at(&self, t: &[u8; 32], i: u32) -> anyhow::Result<Option<ExtractedNoteCommitment>> {
            self.0.cmx_at(t, i)
        }
    }
    let c = build_chain();
    let v = verify_chain(&c.bytes, None, &c.note_in_hand_rho, &Relay(&c.oracle), MIN_DEPTH).unwrap();
    assert_eq!(v.trust, OracleTrust::ServerAsserted);
}

/// An oracle that cannot answer yields `Oracle`, distinct from every forgery verdict.
#[test]
fn oracle_failure_is_unverified_not_forged() {
    struct Broken;
    impl ChainOracle for Broken {
        fn anchor_at(&self, _: &Anchor, _: u32) -> anyhow::Result<AnchorStatus> {
            anyhow::bail!("node down")
        }
        fn cmx_at(&self, _: &[u8; 32], _: u32) -> anyhow::Result<Option<ExtractedNoteCommitment>> {
            anyhow::bail!("node down")
        }
    }
    let c = build_chain();
    assert!(matches!(
        verify_chain(&c.bytes, None, &c.note_in_hand_rho, &Broken, MIN_DEPTH),
        Err(WakeFailure::Oracle(_))
    ));
}
