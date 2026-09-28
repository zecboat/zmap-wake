//! `wake-issuer`: the issuer-side tooling of chapter 9, outside any wallet tree.
//!
//! ```text
//! wake-issuer genesis        --wallet <first holder's copy.db> --txid <hex> --index <n> [--unit <u>] [--zebrad <url>] --out <file>
//! wake-issuer manifest add   --manifest <in.json> --out <out.json> [--ik <hex>] --unit <u:txid:index> [...]
//! wake-issuer manifest check --manifest <file> [--zebrad <url>]
//! wake-issuer pin memo       --manifest <file> [--generation <g>]
//! wake-issuer pin sidecar    --generation <g> --txid <hex> --index <n> --ock <hex> --out <file>
//! wake-issuer pin verify     --manifest <file> --pin <sidecar.json> --address <UA|hex> [--zebrad <url>]
//! wake-issuer pin check-served --manifest-url <U> --pin-url <U> --address <UA|hex> [--zebrad <url>]
//! wake-issuer attest sign    --key <seed.hex> --cmx <hex> --asset-id <hex> --unit <u> --height <h> --out <file>
//! wake-issuer attest verify  --file <attestation.json> [--pubkey <hex>]
//! ```
//!
//! Guardrails: `genesis` reads a wallet COPY (paths under `.AppVault` are refused)
//! and needs only the viewing key. Nothing here builds or sends a transaction;
//! `pin memo` prints the memo for the issuance wallet to send.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::exit;

use anyhow::{anyhow, bail, Context, Result};
use zcash_protocol::consensus::Network;
use zmap_wake::lading::ProofEntry;
use zmap_wake::manifest::{self, GenesisEntry};
use zmap_wake::oracle::{decode_hex_32, hex, ZebradOracle};
use zmap_wake::pin::{self, PinSidecar};
use zmap_wake::wallet_notes::{received_notes_in_tx, witness_at};
use zmap_wake::wallet_path::open_wallet_copy;
use zmap_wake::{attest, prove_genesis, verify_genesis};

const USAGE: &str = "usage: wake-issuer <genesis|manifest|pin|attest> ... (see the module doc)";

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
            let v = it.next().unwrap_or_default();
            flags.entry(name.to_string()).or_default().push(v);
        } else {
            positional.push(a);
        }
    }
    Args { positional, flags }
}

impl Args {
    fn get(&self, name: &str) -> Result<&str> {
        self.flags
            .get(name)
            .and_then(|v| v.first())
            .map(String::as_str)
            .ok_or_else(|| anyhow!("missing --{name}"))
    }
    fn opt(&self, name: &str) -> Option<&str> {
        self.flags.get(name).and_then(|v| v.first()).map(String::as_str)
    }
    fn all(&self, name: &str) -> Vec<&str> {
        self.flags
            .get(name)
            .map(|v| v.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }
    fn zebrad(&self) -> ZebradOracle {
        ZebradOracle::new(self.opt("zebrad").unwrap_or("http://127.0.0.1:8232"))
    }
    fn u32(&self, name: &str) -> Result<u32> {
        self.get(name)?.parse().with_context(|| format!("--{name}"))
    }
}

fn main() {
    let args = parse_args();
    let r = match args.positional.as_slice() {
        [c, ..] if c == "genesis" => cmd_genesis(&args),
        [c, s, ..] if c == "manifest" && s == "add" => cmd_manifest_add(&args),
        [c, s, ..] if c == "manifest" && s == "check" => cmd_manifest_check(&args),
        [c, s, ..] if c == "pin" && s == "memo" => cmd_pin_memo(&args),
        [c, s, ..] if c == "pin" && s == "sidecar" => cmd_pin_sidecar(&args),
        [c, s, ..] if c == "pin" && s == "verify" => cmd_pin_verify(&args, None),
        [c, s, ..] if c == "pin" && s == "check-served" => cmd_pin_check_served(&args),
        [c, s, ..] if c == "attest" && s == "sign" => cmd_attest_sign(&args),
        [c, s, ..] if c == "attest" && s == "verify" => cmd_attest_verify(&args),
        _ => Err(anyhow!("{USAGE}")),
    };
    if let Err(e) = r {
        eprintln!("error: {e:#}");
        exit(1);
    }
}

/// Prove `WAKE_GENESIS` for a mint output from a copy of the wallet that RECEIVED it.
///
/// That is the mint wallet only when the issuer minted to itself. A mint that sends
/// nine outputs to a treasury and one to a collector leaves only those wallets holding
/// the note openings and the `nk` a genesis proof needs (`ZMAP-v0.5.md` §12.3, corrected
/// 2026-09-25). The issuer publishes `genesis[]`; the first holder proves.
fn cmd_genesis(args: &Args) -> Result<()> {
    let wallet = PathBuf::from(args.get("wallet")?);
    let txid_hex = args.get("txid")?.to_lowercase();
    let index = args.u32("index")?;
    let out = PathBuf::from(args.get("out")?);
    let node = args.zebrad();
    let txid = decode_hex_32(&txid_hex)?;

    let notes = received_notes_in_tx(&wallet, Network::MainNetwork, &txid)?;
    let n = notes
        .iter()
        .find(|n| n.action_index == index)
        .ok_or_else(|| anyhow!("the wallet did not receive Action {index} of {txid_hex}"))?;
    eprintln!(
        "mint output: Action {} value {} position {:?} height {}",
        n.action_index, n.value, n.position, n.mined_height
    );

    // The oracle's view of the same output must agree before we prove anything.
    let (_, actions) = node
        .ironwood_actions(&txid_hex)?
        .ok_or_else(|| anyhow!("node does not know {txid_hex} as mined"))?;
    let on_chain = actions
        .get(index as usize)
        .ok_or_else(|| anyhow!("node reports no Action {index}"))?;
    if on_chain.cmx != n.cmx().to_bytes() {
        bail!("the node's cmx at that output is not this note's commitment");
    }

    let db = open_wallet_copy(&wallet, Network::MainNetwork)?;
    let ts = node.ironwood_tree_state(n.mined_height)?;
    let w = witness_at(&db, n, &ts)?;
    zmap_wake::keys::warm();
    let proof = prove_genesis(&w)?;
    verify_genesis(&proof.proof, &proof.instance)?;
    let entry = ProofEntry::from_proof(&proof, n.mined_height);

    let record = serde_json::json!({
        "unit": args.opt("unit").and_then(|u| u.parse::<u32>().ok()),
        "genesis": { "txid": txid_hex, "action_index": index },
        "cmx": hex(&n.cmx().to_bytes()),
        "entry": entry,
    });
    std::fs::write(&out, serde_json::to_string_pretty(&record)?)?;
    println!("genesis proof written to {} ({} bytes)", out.display(), proof.proof.len());
    Ok(())
}

fn cmd_manifest_add(args: &Args) -> Result<()> {
    let input = std::fs::read(args.get("manifest")?)?;
    let entries: Vec<GenesisEntry> = args
        .all("unit")
        .iter()
        .map(|s| GenesisEntry::parse(s))
        .collect::<Result<_>>()?;
    let out = manifest::add_genesis(&input, args.opt("ik"), &entries)?;
    std::fs::write(args.get("out")?, &out)?;
    println!(
        "wrote {} with {} genesis entries; this is a NEW generation: bump `generation`, sign, pin",
        args.get("out")?,
        entries.len()
    );
    Ok(())
}

fn cmd_manifest_check(args: &Args) -> Result<()> {
    let input = std::fs::read(args.get("manifest")?)?;
    let entries = manifest::read_genesis(&input)?;
    if entries.is_empty() {
        bail!("manifest has no genesis[]");
    }
    let node = args.zebrad();
    let mut bad = 0;
    for (unit, r) in manifest::check_genesis(&entries, &node) {
        match r {
            Ok(cmx) => println!("unit {unit}: on chain, cmx {}", hex(&cmx.to_bytes())),
            Err(e) => {
                bad += 1;
                println!("unit {unit}: NOT CONFIRMED: {e}")
            }
        }
    }
    if let Some((total, n)) = manifest::check_finalization(&input)? {
        println!(
            "finalization total_units {total} vs len(genesis[]) {n}: {}",
            if total as usize == n { "ok" } else { "MISMATCH (§13)" }
        );
    }
    if bad > 0 {
        bail!("{bad} genesis entries not confirmed");
    }
    Ok(())
}

fn cmd_pin_memo(args: &Args) -> Result<()> {
    let bytes = std::fs::read(args.get("manifest")?)?;
    let g = match args.opt("generation") {
        Some(g) => g.parse()?,
        None => manifest::generation(&bytes)?,
    };
    let memo = pin::pin_memo(g, &bytes);
    println!("manifest bytes: {}", bytes.len());
    println!("sha256:         {}", hex(&pin::manifest_hash(&bytes)));
    println!("generation:     {g}");
    println!("memo (52 bytes, then NUL to 512), hex:");
    println!("{}", hex(&memo[..pin::PIN_MEMO_LEN]));
    println!("memo, full 512 bytes, hex:");
    println!("{}", hex(&memo));
    println!("send one shielded output FROM the issuance address TO the issuance address with this memo;");
    println!("after it mines, derive the OCK for that output and write the sidecar (`pin sidecar`).");
    Ok(())
}

fn cmd_pin_sidecar(args: &Args) -> Result<()> {
    let sc = PinSidecar {
        generation: args.u32("generation")?,
        txid: args.get("txid")?.to_lowercase(),
        action_index: args.u32("index")?,
        ock: args.get("ock")?.to_lowercase(),
    };
    decode_hex_32(&sc.txid).context("txid")?;
    decode_hex_32(&sc.ock).context("ock")?;
    std::fs::write(args.get("out")?, serde_json::to_string_pretty(&sc)? + "\n")?;
    println!("sidecar written to {}", args.get("out")?);
    Ok(())
}

fn verify_pin_bytes(args: &Args, manifest_bytes: &[u8], sidecar: &PinSidecar) -> Result<()> {
    let address = pin::parse_orchard_address(args.get("address")?, Network::MainNetwork)?;
    let g = manifest::generation(manifest_bytes)?;
    let node = args.zebrad();
    match pin::verify_pin(manifest_bytes, g, sidecar, &address, &node, Network::MainNetwork) {
        Ok(v) => {
            println!(
                "PINNED: generation {} at height {}, sha256 {}",
                v.generation,
                v.height,
                hex(&v.manifest_hash)
            );
            Ok(())
        }
        Err(pin::PinFailure::SplitView) => {
            println!("SPLIT VIEW: the chain pins different manifest bytes for generation {g}");
            bail!("split view")
        }
        Err(e) => bail!("pin does not verify: {e}"),
    }
}

fn cmd_pin_verify(args: &Args, _: Option<()>) -> Result<()> {
    let manifest_bytes = std::fs::read(args.get("manifest")?)?;
    let sidecar: PinSidecar = serde_json::from_slice(&std::fs::read(args.get("pin")?)?)?;
    verify_pin_bytes(args, &manifest_bytes, &sidecar)
}

/// The §7.3.1 rule made executable: hash what is SERVED, after deployment.
fn cmd_pin_check_served(args: &Args) -> Result<()> {
    let manifest_bytes = pin::fetch_url(args.get("manifest-url")?)?;
    let sidecar: PinSidecar = serde_json::from_slice(&pin::fetch_url(args.get("pin-url")?)?)?;
    println!("fetched {} manifest bytes", manifest_bytes.len());
    verify_pin_bytes(args, &manifest_bytes, &sidecar)
}

fn cmd_attest_sign(args: &Args) -> Result<()> {
    let seed = attest::read_seed(&PathBuf::from(args.get("key")?))?;
    let cmx = decode_hex_32(args.get("cmx")?)?;
    let asset_id = pin::decode_hex(args.get("asset-id")?)?;
    let a = attest::sign(&seed, &cmx, &asset_id, args.u32("unit")?, args.u32("height")?);
    std::fs::write(args.get("out")?, serde_json::to_string_pretty(&a)? + "\n")?;
    println!("attestation written to {} (key {})", args.get("out")?, a.attestation_key);
    Ok(())
}

fn cmd_attest_verify(args: &Args) -> Result<()> {
    let a: attest::Attestation = serde_json::from_slice(&std::fs::read(args.get("file")?)?)?;
    let expected = match args.opt("pubkey") {
        Some(k) => Some(decode_hex_32(k)?),
        None => None,
    };
    let cmx = attest::verify(&a, expected.as_ref())?;
    println!(
        "attestation verifies: unit {} of {} at height {}, cmx {}{}",
        a.unit,
        a.asset_id,
        a.height,
        hex(&cmx),
        if expected.is_none() {
            " (NO pinned key given: internal consistency only)"
        } else {
            ""
        }
    );
    Ok(())
}
