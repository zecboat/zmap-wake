//! Feasibility check (2026-10-05): verify the ladings held in a wallet COPY against a
//! lightwalletd-protocol server, with no full node on this machine.
//!
//!   cargo run --release --features lightwalletd --example light_verify -- <wallet-copy.db> <server-url>
//!
//! Reads the copy read-only (the `.AppVault` guard applies). For every lading tied to a received
//! note it runs the same `verify_chain` the wallet runs, only with [`LightwalletdOracle`] in
//! place of the zebrad one, and prints the verdict with the oracle's trust level.
//!
//! Then, per lading: three negative checks that depend on the server's answers (a wrong anchor
//! height, a wrong genesis output, a wrong note in hand), and the sender's side: the next hop is
//! proved from the server's tree state and the wallet's own shards, as a send would do, and the
//! extended lading is verified again. Nothing is written or broadcast.

use anyhow::{anyhow, Context, Result};
use ff::PrimeField;
use orchard::note::Rho;
use std::path::Path;
use zcash_protocol::consensus::Network;
use zmap_wake::lading::{Lading, ProofEntry};
use zmap_wake::oracle::{reversed, OracleTrust, MIN_DEPTH};
use zmap_wake::oracle_lightwalletd::LightwalletdOracle;
use zmap_wake::wallet_notes::{received_notes_in_tx, witness_at};
use zmap_wake::wallet_path::{open_wallet_copy, open_wallet_copy_sql};
use zmap_wake::{prove_hop, verify_chain};

fn rho_of(bytes: &[u8; 32]) -> Result<Rho> {
    Option::from(Rho::from_bytes(bytes)).context("not a field element")
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        return Err(anyhow!("usage: light_verify <wallet-copy.db> <server-url>"));
    }
    let conn = open_wallet_copy_sql(&args[1])?;
    let oracle = LightwalletdOracle::new(args[2].clone(), Network::MainNetwork)?;
    let started = std::time::Instant::now();
    println!("server {}  tip {}", args[2], oracle.tip_height()?);

    let mut stmt = conn.prepare(
        "SELECT c.id, c.asset_id, c.json, c.sha256, n.rho, n.id, t.txid \
         FROM ext_zecboat_zmap_consignments c \
         JOIN ironwood_received_notes n ON n.id = c.received_note_id \
         JOIN transactions t ON t.id_tx = n.transaction_id \
         ORDER BY c.id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Vec<u8>>(2)?,
            r.get::<_, Vec<u8>>(3)?,
            r.get::<_, Vec<u8>>(4)?,
            r.get::<_, i64>(5)?,
            r.get::<_, Vec<u8>>(6)?,
        ))
    })?;
    let wallet = open_wallet_copy(&args[1], Network::MainNetwork)?;
    zmap_wake::keys::warm();

    let (mut ok, mut bad) = (0, 0);
    for row in rows {
        let (id, asset_id, json, sha, rho, note_row, txid_internal) = row?;
        let expected: [u8; 32] = sha.as_slice().try_into().map_err(|_| anyhow!("lading {id}: stored hash is not 32 bytes"))?;
        let rho_bytes: [u8; 32] = rho.as_slice().try_into().map_err(|_| anyhow!("lading {id}: rho is not 32 bytes"))?;
        let rho: Rho = rho_of(&rho_bytes)?;
        let hops = Lading::parse(&json).map(|l| l.hops.len()).unwrap_or(0);
        let t = std::time::Instant::now();
        match verify_chain(&json, Some(expected), &rho, &oracle, MIN_DEPTH) {
            Ok(v) => {
                ok += 1;
                println!(
                    "lading {id}  asset {}…  hops {hops}  {}  min anchor depth {}  ({:.1}s)",
                    &asset_id[..16.min(asset_id.len())],
                    match v.trust { OracleTrust::FullNode => "Verified (own node)", OracleTrust::ServerAsserted => "Checked via provider (not verified)" },
                    v.min_anchor_depth, t.elapsed().as_secs_f64()
                );
            }
            Err(e) => {
                bad += 1;
                println!("lading {id}  asset {}…  hops {hops}  FAILED: {e:?}  ({:.1}s)", &asset_id[..16.min(asset_id.len())], t.elapsed().as_secs_f64());
            }
        }

        // Negative checks: each must FAIL, and for the stated reason.
        let mut l = Lading::parse(&json).map_err(|e| anyhow!("{e:?}"))?;
        l.hops[0].anchor_height -= 1;
        let r = verify_chain(&l.to_bytes(), None, &rho, &oracle, MIN_DEPTH);
        println!("    wrong anchor height  -> {}", match &r { Ok(_) => "ACCEPTED (BAD)".to_string(), Err(e) => format!("refused: {e:?}") });
        let mut l = Lading::parse(&json).map_err(|e| anyhow!("{e:?}"))?;
        l.genesis.action_index ^= 1;
        let r = verify_chain(&l.to_bytes(), None, &rho, &oracle, MIN_DEPTH);
        println!("    wrong genesis output -> {}", match &r { Ok(_) => "ACCEPTED (BAD)".to_string(), Err(e) => format!("refused: {e:?}") });
        let mut other = rho_bytes; other[0] ^= 1;
        if let Ok(other) = rho_of(&other) {
            let r = verify_chain(&json, Some(expected), &other, &oracle, MIN_DEPTH);
            println!("    wrong note in hand   -> {}", match &r { Ok(_) => "ACCEPTED (BAD)".to_string(), Err(e) => format!("refused: {e:?}") });
        }

        // The sender's side: prove the next hop from the SERVER's tree state, as a send would.
        let txid: [u8; 32] = txid_internal.as_slice().try_into().map_err(|_| anyhow!("txid is not 32 bytes"))?;
        let note = received_notes_in_tx(Path::new(&args[1]), Network::MainNetwork, &reversed(txid))?
            .into_iter()
            .find(|n| n.row_id == note_row)
            .ok_or_else(|| anyhow!("lading {id}: note row {note_row} not found"))?;
        let t = std::time::Instant::now();
        let ts = oracle.ironwood_tree_state(note.mined_height)?;
        let w = witness_at(&wallet, &note, &ts)?;
        let proof = prove_hop(&w).map_err(|e| anyhow!("hop proof failed: {e:?}"))?;
        let proved = t.elapsed().as_secs_f64();
        let mut l = Lading::parse(&json).map_err(|e| anyhow!("{e:?}"))?;
        l.hops.push(ProofEntry::from_proof(&proof, note.mined_height));
        let next_rho = rho_of(&proof.instance[2].to_repr())?;
        let t = std::time::Instant::now();
        match verify_chain(&l.to_bytes(), None, &next_rho, &oracle, MIN_DEPTH) {
            Ok(v) => println!("    next hop proved from the server's tree state in {proved:.1}s; {}-hop lading verifies ({:.1}s), {} bytes", v.hops, t.elapsed().as_secs_f64(), l.to_bytes().len()),
            Err(e) => { bad += 1; println!("    next hop proved in {proved:.1}s but the extended lading FAILED: {e:?}") }
        }
    }
    println!("{ok} passed (checked via provider, not verified), {bad} failed, {:.1}s in all", started.elapsed().as_secs_f64());
    Ok(())
}
