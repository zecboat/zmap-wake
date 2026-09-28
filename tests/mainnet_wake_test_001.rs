//! A complete real chain on Zcash mainnet: Wake Test #001, three proofs, between THROWAWAY
//! wallets made for this purpose, so the chain links nothing anyone owns and can be published.
//!
//! ```text
//! mint   14b8a35a… h3,496,071  Action 2  ->  testA note    (genesis)          nf_0 849a4ce1…
//! T1     9d264ae2… h3,496,139  Action 0  ->  testB note    rho = nf_0         nf_1 db274b67…
//! T2     b39fabe0… h3,497,264  Action 0  ->  testA note    rho = nf_1         nf_2 c208b530…
//! T3     657edc1e… h3,497,280  Action 1  ->  testB note    rho = nf_2         (the note in hand)
//! ```
//!
//! Every transfer was made by the Zecboat wallet with Action pairing (ZMAP v0.5 §5.5).
//!
//! Two tests, both ignored by default because they need a synced zebrad:
//!
//! - `wake_test_001_published_lading_verifies` needs **only a node**. It verifies the published
//!   lading `docs/test_vector/wake_test_001_lading.json` exactly as a recipient would, so a
//!   reviewer can run it:
//!
//!   ```sh
//!   cargo test --release --test mainnet_wake_test_001 wake_test_001_published -- --ignored --nocapture
//!   ```
//!
//! - `wake_test_001_rebuilt_from_wallet_copies` also needs COPIES of the testA and testB wallets.
//!   It re-derives the three notes, checks the consensus links, proves every hop from each
//!   holder's own wallet, and checks the result against the published lading:
//!
//!   ```sh
//!   WAKE_TESTA_COPY=<testA wallet.db copy> WAKE_TESTB_COPY=<testB wallet.db copy> \
//!   cargo test --release --test mainnet_wake_test_001 wake_test_001_rebuilt -- --ignored --nocapture
//!   ```
//!
//! What they establish: the genesis proof is made by the mint output's first holder (testA),
//! each hop proof by the holder of that hop's note; the lading verifies under `verify_chain`
//! against a full node with `MIN_DEPTH`; and the wrong note in hand fails with `RhoMismatch`.

use std::env;
use std::path::PathBuf;
use std::time::Instant;

use ff::PrimeField;
use orchard::note::Rho;
use zcash_protocol::consensus::Network;
use zmap_wake::lading::{lading_hash, Lading, ProofEntry};
use zmap_wake::oracle::{decode_hex_32, hex, ChainOracle, OracleTrust, ZebradOracle, MIN_DEPTH};
use zmap_wake::verify::{verify_chain, WakeFailure};
use zmap_wake::wallet_notes::{received_notes_in_tx, witness_at};
use zmap_wake::wallet_path::open_wallet_copy;
use zmap_wake::{prove_genesis, prove_hop};

const MINT: &str = "14b8a35a93fec522b597115e18e5100885c30964f222a998cd8325df9118f362";
const MINT_ACTION: u32 = 2;
const T1: &str = "9d264ae2e6c648c8add4925c7653b178dca0c508819bd5ea6764a52326e60895";
const T1_ACTION: u32 = 0;
const T2: &str = "b39fabe028775ebfbff672ffacb32f13c109ce249f9b53f8f7a1d23c08d7db0b";
const T2_ACTION: u32 = 0;
const T3: &str = "657edc1e7287289abd102a468943966e8183f4509b28bfa3499e5ce576d712c9";
const T3_ACTION: u32 = 1;

/// The published lading, byte for byte as the wallet delivered it.
const LADING_SHA256: &str = "0cc8e1c098d1d992e15e56067b0edafefcb855d8b681ed9bb26fa652c92427e1";
/// ρ of the note in hand (testB's output of T3) = nf_2, the final proof's `nf`.
const RHO_IN_HAND: &str = "c208b5304d072f05e40142cce0026e6faa4961b83b7ae81ac255013aad404a39";

fn published_lading() -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/test_vector/wake_test_001_lading.json");
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn rho(hex_str: &str) -> Rho {
    Option::<Rho>::from(Rho::from_bytes(&decode_hex_32(hex_str).unwrap())).expect("canonical rho")
}

fn node() -> ZebradOracle {
    ZebradOracle::new(env::var("WAKE_ZEBRAD").unwrap_or_else(|_| "http://127.0.0.1:8232".into()))
}

#[test]
#[ignore = "needs a synced zebrad; see the module doc"]
fn wake_test_001_published_lading_verifies() {
    let bytes = published_lading();
    let hash = lading_hash(&bytes);
    assert_eq!(hex(&hash), LADING_SHA256, "the test vector is not the published lading");

    let lading = Lading::parse(&bytes).expect("lading parses");
    assert_eq!(lading.genesis.txid, MINT);
    assert_eq!(lading.genesis.action_index, MINT_ACTION);
    assert_eq!(lading.hops.len(), 3);

    let node = node();
    let t = Instant::now();
    let v = verify_chain(&bytes, Some(hash), &rho(RHO_IN_HAND), &node, MIN_DEPTH).expect("chain verifies");
    println!("verify_chain in {:.2?}: {v:?}", t.elapsed());
    assert_eq!(v.hops, 3);
    assert_eq!(v.trust, OracleTrust::FullNode);
    assert_eq!(hex(&v.final_nf), RHO_IN_HAND);
    assert!(v.min_anchor_depth >= MIN_DEPTH);

    // The genesis commitment the proof claims is the one the node holds at the mint output.
    let on_chain = node.cmx_at(&decode_hex_32(MINT).unwrap(), MINT_ACTION).unwrap().expect("mint output on chain");
    assert_eq!(v.genesis_cmx, on_chain.to_bytes());

    // The same lading presented with the wrong note in hand: testA's T2 note, whose rho is nf_1.
    assert_eq!(
        verify_chain(&bytes, Some(hash), &rho(&lading.hops[1].instance[2]), &node, MIN_DEPTH),
        Err(WakeFailure::RhoMismatch)
    );
}

#[test]
#[ignore = "needs wallet COPIES of testA and testB and a synced zebrad; see the module doc"]
fn wake_test_001_rebuilt_from_wallet_copies() {
    let a = PathBuf::from(env::var("WAKE_TESTA_COPY").expect("set WAKE_TESTA_COPY to a testA wallet.db COPY"));
    let b = PathBuf::from(env::var("WAKE_TESTB_COPY").expect("set WAKE_TESTB_COPY to a testB wallet.db COPY"));
    let node = node();
    let net = Network::MainNetwork;

    let find = |wallet: &PathBuf, txid: &str, action: u32, what: &str| {
        received_notes_in_tx(wallet, net, &decode_hex_32(txid).unwrap())
            .unwrap_or_else(|e| panic!("{what}: {e}"))
            .into_iter()
            .find(|n| n.action_index == action)
            .unwrap_or_else(|| panic!("{what}: not in this wallet"))
    };

    // ---- the four notes -----------------------------------------------------------------
    let g = find(&a, MINT, MINT_ACTION, "testA's mint output (genesis)");
    let n1 = find(&b, T1, T1_ACTION, "testB's T1 note (hop 1)");
    let n2 = find(&a, T2, T2_ACTION, "testA's T2 note (hop 2)");
    let h = find(&b, T3, T3_ACTION, "testB's T3 note (in hand)");
    for (label, n) in [("genesis", &g), ("hop 1", &n1), ("hop 2", &n2), ("in hand", &h)] {
        println!("{label}: h {} action {} value {} position {:?}", n.mined_height, n.action_index, n.value, n.position);
        assert_eq!(n.value, 10_000, "{label} is not a 10,000-zat carrier");
    }

    // The chain, as consensus already recorded it.
    let nf_0 = g.note.nullifier(&g.fvk).to_bytes();
    let nf_1 = n1.note.nullifier(&n1.fvk).to_bytes();
    let nf_2 = n2.note.nullifier(&n2.fvk).to_bytes();
    assert_eq!(n1.note.rho().to_bytes(), nf_0, "hop 1's rho is not the genesis nf");
    assert_eq!(n2.note.rho().to_bytes(), nf_1, "hop 2's rho is not hop 1's nf");
    assert_eq!(h.note.rho().to_bytes(), nf_2, "the note in hand's rho is not hop 2's nf");
    assert_eq!(hex(&nf_2), RHO_IN_HAND);
    println!("consensus links hold: rho_1 == nf_0, rho_2 == nf_1, rho_3 == nf_2");

    // ---- proofs, each from its holder's own wallet ---------------------------------------
    let a_db = open_wallet_copy(&a, net).expect("open testA copy");
    let b_db = open_wallet_copy(&b, net).expect("open testB copy");
    zmap_wake::keys::warm();

    let t = Instant::now();
    let pg = prove_genesis(&witness_at(&a_db, &g, &node.ironwood_tree_state(g.mined_height).unwrap()).expect("genesis witness"))
        .expect("genesis proof");
    let p1 = prove_hop(&witness_at(&b_db, &n1, &node.ironwood_tree_state(n1.mined_height).unwrap()).expect("hop 1 witness"))
        .expect("hop 1 proof");
    let p2 = prove_hop(&witness_at(&a_db, &n2, &node.ironwood_tree_state(n2.mined_height).unwrap()).expect("hop 2 witness"))
        .expect("hop 2 proof");
    println!("three proofs in {:.2?}", t.elapsed());
    assert_eq!(p1.instance[1].to_repr(), nf_0);
    assert_eq!(p2.instance[1].to_repr(), nf_1);
    assert_eq!(p2.instance[2].to_repr(), nf_2);

    let mut lading = Lading::new(MINT, MINT_ACTION);
    lading.hops.push(ProofEntry::from_proof(&pg, g.mined_height));
    lading.hops.push(ProofEntry::from_proof(&p1, n1.mined_height));
    lading.hops.push(ProofEntry::from_proof(&p2, n2.mined_height));
    let bytes = lading.to_bytes();

    let v = verify_chain(&bytes, Some(lading_hash(&bytes)), &h.note.rho(), &node, MIN_DEPTH).expect("rebuilt chain verifies");
    assert_eq!(v.hops, 3);
    assert_eq!(v.trust, OracleTrust::FullNode);

    // Proofs are randomised, so the bytes differ from the published lading; the public
    // instances (anchor, link in, nf out) and anchor heights must not.
    let published = Lading::parse(&published_lading()).unwrap();
    for (j, (mine, theirs)) in lading.hops.iter().zip(&published.hops).enumerate() {
        assert_eq!(mine.circuit, theirs.circuit, "proof {j}: circuit");
        assert_eq!(mine.instance, theirs.instance, "proof {j}: instance");
        assert_eq!(mine.anchor_height, theirs.anchor_height, "proof {j}: anchor height");
    }
    println!("rebuilt lading matches the published instances for all 3 proofs");
}
