//! `wake-holder`: the holder side, from wallet COPIES. What a wallet would do in
//! chapter 8, as commands, so a chain can be built and checked by hand.
//!
//! ```text
//! wake-holder notes    --wallet <copy.db> --txid <hex>
//!     every Ironwood note that wallet received in the transaction: index, value, ZMAP asset, rho, nf
//!
//! wake-holder pairing  --sender <copy.db> --recipient <copy.db> --txid <hex>
//!     did the carrier's lineage reach the recipient? For each note the recipient received,
//!     which of the sender's spent notes has nf == that rho. §5.5 made checkable after the fact.
//!
//! wake-holder lading   --genesis <copy.db>:<txid>:<index> [--hop <copy.db>:<txid>:<index> ...]
//!                      --in-hand <copy.db>:<txid>:<index> --out <lading.json> [--zebrad <url>]
//!     prove the genesis and every hop from the named wallet copies, write the lading, and
//!     verify it against zebrad with the in-hand note's rho. Also writes <out>.record.json.
//!
//! wake-holder verify   --lading <file> --rho <hex> [--hash <hex>] [--zebrad <url>]
//!     verify_chain on a delivered lading, as a recipient would.
//! ```
//!
//! Every wallet path goes through the `.AppVault` guard: copies only.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::exit;
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use ff::PrimeField;
use orchard::note::Rho;
use zcash_protocol::consensus::Network;
use zmap_wake::lading::{lading_hash, Lading, ProofEntry};
use zmap_wake::oracle::{decode_hex_32, hex, ZebradOracle, MIN_DEPTH};
use zmap_wake::verify::verify_chain;
use zmap_wake::wallet_notes::{received_notes_in_tx, spent_notes_in_tx, witness_at, ReceivedNote};
use zmap_wake::wallet_path::open_wallet_copy;
use zmap_wake::{prove_genesis, prove_hop};

const USAGE: &str = "usage: wake-holder <notes|pairing|lading|verify> ... (see the module doc)";
const NET: Network = Network::MainNetwork;

struct Args {
    positional: Vec<String>,
    flags: HashMap<String, Vec<String>>,
}

fn parse_args() -> Args {
    let mut positional = Vec::new();
    let mut flags: HashMap<String, Vec<String>> = HashMap::new();
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        if let Some(name) = a.strip_prefix("--") {
            flags.entry(name.to_string()).or_default().push(it.next().unwrap_or_default());
        } else {
            positional.push(a);
        }
    }
    Args { positional, flags }
}

impl Args {
    fn get(&self, name: &str) -> Result<&str> {
        self.opt(name).ok_or_else(|| anyhow!("missing --{name}"))
    }
    fn opt(&self, name: &str) -> Option<&str> {
        self.flags.get(name).and_then(|v| v.first()).map(String::as_str)
    }
    fn all(&self, name: &str) -> Vec<&str> {
        self.flags.get(name).map(|v| v.iter().map(String::as_str).collect()).unwrap_or_default()
    }
    fn zebrad(&self) -> ZebradOracle {
        ZebradOracle::new(self.opt("zebrad").unwrap_or("http://127.0.0.1:8232"))
    }
}

fn main() {
    let args = parse_args();
    let r = match args.positional.first().map(String::as_str) {
        Some("notes") => cmd_notes(&args),
        Some("pairing") => cmd_pairing(&args),
        Some("lading") => cmd_lading(&args),
        Some("verify") => cmd_verify(&args),
        _ => Err(anyhow!("{USAGE}")),
    };
    if let Err(e) = r {
        eprintln!("error: {e:#}");
        exit(1);
    }
}

fn describe(n: &ReceivedNote) -> String {
    let asset = n
        .zmap_asset_id()
        .map(|a| format!("ZMAP {}…", &a[..a.len().min(8)]))
        .unwrap_or_else(|| if n.is_change { "change".into() } else { "plain".into() });
    format!(
        "action {} value {:>7} {:<14} pos {:<8} rho {}… nf {}…",
        n.action_index,
        n.value,
        asset,
        n.position.map(|p| p.to_string()).unwrap_or("?".into()),
        &hex(&n.note.rho().to_bytes())[..16],
        n.stored_nf.map(|f| hex(&f)[..16].to_string()).unwrap_or("?".into())
    )
}

fn cmd_notes(args: &Args) -> Result<()> {
    let wallet = PathBuf::from(args.get("wallet")?);
    let txid = decode_hex_32(args.get("txid")?)?;
    let notes = received_notes_in_tx(&wallet, NET, &txid)?;
    if notes.is_empty() {
        bail!("that wallet received no Ironwood notes in that transaction");
    }
    println!("mined at {}", notes[0].mined_height);
    for n in &notes {
        println!("  {}", describe(n));
    }
    Ok(())
}

/// For each note the recipient received, name the sender's spent note whose nf is its rho.
fn cmd_pairing(args: &Args) -> Result<()> {
    let sender = PathBuf::from(args.get("sender")?);
    let recipient = PathBuf::from(args.get("recipient")?);
    let txid = decode_hex_32(args.get("txid")?)?;
    let spent = spent_notes_in_tx(&sender, NET, &txid)?;
    if spent.is_empty() {
        bail!("the sender wallet records no notes spent in that transaction");
    }
    println!("sender spent {} note(s):", spent.len());
    for s in &spent {
        println!("  {}", describe(s));
    }
    let received = received_notes_in_tx(&recipient, NET, &txid)?;
    println!("recipient received {} note(s):", received.len());
    let mut ok = 0;
    for r in &received {
        let rho = r.note.rho().to_bytes();
        let from = spent.iter().find(|s| s.stored_nf == Some(rho));
        let verdict = match (from, r.zmap_asset_id()) {
            (Some(s), Some(_)) if s.zmap_asset_id().is_some() => {
                ok += 1;
                "PAIRED: carrier spend -> carrier output, lineage delivered".to_string()
            }
            (Some(s), Some(_)) => format!(
                "MIS-PAIRED: memo carrier's rho is the nf of the sender's {} note (action {})",
                if s.is_change { "change" } else { "fee/plain" },
                s.action_index
            ),
            (Some(s), None) => format!("plain output, successor of sender's action-{} note", s.action_index),
            (None, _) => "rho matches none of the sender's spent notes".to_string(),
        };
        println!("  {}\n      {verdict}", describe(r));
    }
    // Where did each spent carrier's lineage go?
    for s in spent.iter().filter(|s| s.zmap_asset_id().is_some()) {
        let nf = s.stored_nf.ok_or_else(|| anyhow!("spent carrier without nf"))?;
        let successor_in_recipient = received.iter().any(|r| r.note.rho().to_bytes() == nf);
        if !successor_in_recipient {
            let sender_notes = received_notes_in_tx(&sender, NET, &txid).unwrap_or_default();
            match sender_notes.iter().find(|n| n.note.rho().to_bytes() == nf) {
                Some(c) => println!(
                    "  lineage of spent carrier (action {}) sits in the SENDER's note: {}",
                    s.action_index,
                    describe(c)
                ),
                None => println!(
                    "  lineage of spent carrier (action {}) not found in either wallet copy",
                    s.action_index
                ),
            }
        }
    }
    if ok == 0 {
        bail!("no carrier was delivered with its lineage in this transaction");
    }
    println!("{ok} carrier(s) delivered with lineage");
    Ok(())
}

fn parse_ref(s: &str) -> Result<(PathBuf, [u8; 32], u32)> {
    let parts: Vec<&str> = s.rsplitn(3, ':').collect();
    if parts.len() != 3 {
        bail!("expected <copy.db>:<txid>:<index>, got {s:?}");
    }
    let index: u32 = parts[0].parse().context("index")?;
    let txid = decode_hex_32(parts[1]).context("txid")?;
    Ok((PathBuf::from(parts[2]), txid, index))
}

fn note_at(wallet: &PathBuf, txid: &[u8; 32], index: u32) -> Result<ReceivedNote> {
    received_notes_in_tx(wallet, NET, txid)?
        .into_iter()
        .find(|n| n.action_index == index)
        .ok_or_else(|| anyhow!("{} did not receive action {index} of {}", wallet.display(), hex(txid)))
}

fn cmd_lading(args: &Args) -> Result<()> {
    let node = args.zebrad();
    let (g_wallet, g_txid, g_idx) = parse_ref(args.get("genesis")?)?;
    let hops: Vec<_> = args.all("hop").iter().map(|h| parse_ref(h)).collect::<Result<_>>()?;
    let (h_wallet, h_txid, h_idx) = parse_ref(args.get("in-hand")?)?;
    let out = PathBuf::from(args.get("out")?);

    zmap_wake::keys::warm();
    let mut lading = Lading::new(&hex(&g_txid), g_idx);

    let g = note_at(&g_wallet, &g_txid, g_idx)?;
    println!("genesis:  {}", describe(&g));
    let t = Instant::now();
    let db = open_wallet_copy(&g_wallet, NET)?;
    let ts = node.ironwood_tree_state(g.mined_height)?;
    let w = witness_at(&db, &g, &ts)?;
    let p = prove_genesis(&w)?;
    lading.hops.push(ProofEntry::from_proof(&p, g.mined_height));
    println!("          proved in {:.1?}", t.elapsed());
    let mut prev_nf = g.note.nullifier(&g.fvk).to_bytes();

    for (i, (wallet, txid, idx)) in hops.iter().enumerate() {
        let n = note_at(wallet, txid, *idx)?;
        println!("hop {}:    {}", i + 1, describe(&n));
        if n.note.rho().to_bytes() != prev_nf {
            bail!("hop {}: rho is not the previous note's nf; the chain is broken here", i + 1);
        }
        let t = Instant::now();
        let db = open_wallet_copy(wallet, NET)?;
        let ts = node.ironwood_tree_state(n.mined_height)?;
        let w = witness_at(&db, &n, &ts)?;
        let p = prove_hop(&w)?;
        lading.hops.push(ProofEntry::from_proof(&p, n.mined_height));
        println!("          proved in {:.1?}", t.elapsed());
        prev_nf = n.note.nullifier(&n.fvk).to_bytes();
    }

    let h = note_at(&h_wallet, &h_txid, h_idx)?;
    println!("in hand:  {}", describe(&h));
    if h.note.rho().to_bytes() != prev_nf {
        bail!("the note in hand's rho is not the last hop's nf; the chain is broken at the end");
    }

    let bytes = lading.to_bytes();
    let hash = lading_hash(&bytes);
    let t = Instant::now();
    let v = match verify_chain(&bytes, Some(hash), &h.note.rho(), &node, MIN_DEPTH) {
        Ok(v) => v,
        Err(zmap_wake::WakeFailure::AnchorTooShallow { hop, depth }) => {
            // Not wrong, not yet safe (WAKE-v1 §8). Write it anyway; it needs only time.
            std::fs::write(&out, &bytes)?;
            let entry = &lading.hops[hop];
            let safe_at = entry.anchor_height + MIN_DEPTH;
            println!(
                "NOT YET SAFE: hop {hop}'s anchor is {depth} blocks deep, {MIN_DEPTH} required. \
                 Lading written to {} (sha256 {}); re-verify once the tip reaches {safe_at}:\n  \
                 wake-holder verify --lading {} --rho {} --hash {}",
                out.display(),
                hex(&hash),
                out.display(),
                hex(&h.note.rho().to_bytes()),
                hex(&hash)
            );
            return Ok(());
        }
        Err(e) => bail!("the lading does NOT verify: {e}"),
    };
    println!(
        "verified: {} proof(s), trust {:?}, shallowest anchor {} deep, in {:.1?}",
        v.hops,
        v.trust,
        v.min_anchor_depth,
        t.elapsed()
    );
    std::fs::write(&out, &bytes)?;
    let rec = serde_json::json!({
        "lading_sha256": hex(&hash),
        "note_in_hand": { "txid": hex(&h_txid), "action_index": h_idx, "rho": hex(&h.note.rho().to_bytes()) },
        "genesis_cmx": hex(&v.genesis_cmx),
        "final_nf": hex(&v.final_nf),
        "min_anchor_depth": v.min_anchor_depth,
    });
    let rec_path = out.with_extension("record.json");
    std::fs::write(&rec_path, serde_json::to_string_pretty(&rec)?)?;
    println!("written {} ({} bytes) and {}", out.display(), bytes.len(), rec_path.display());
    Ok(())
}

fn cmd_verify(args: &Args) -> Result<()> {
    let bytes = std::fs::read(args.get("lading")?)?;
    let rho_bytes = decode_hex_32(args.get("rho")?)?;
    let rho = Option::<Rho>::from(Rho::from_bytes(&rho_bytes)).ok_or_else(|| anyhow!("non-canonical rho"))?;
    let hash = match args.opt("hash") {
        Some(h) => Some(decode_hex_32(h)?),
        None => None,
    };
    let _ = pallas_check(&rho_bytes);
    match verify_chain(&bytes, hash, &rho, &args.zebrad(), MIN_DEPTH) {
        Ok(v) => {
            println!(
                "VERIFIED: {} proof(s), trust {:?}, genesis cmx {}, shallowest anchor {} deep",
                v.hops,
                v.trust,
                hex(&v.genesis_cmx),
                v.min_anchor_depth
            );
            Ok(())
        }
        Err(e) => bail!("NOT verified: {e}"),
    }
}

fn pallas_check(b: &[u8; 32]) -> bool {
    bool::from(pasta_curves::pallas::Base::from_repr(*b).is_some())
}
