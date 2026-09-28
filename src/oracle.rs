//! Chain oracles (`WAKE-v1.md` §8.1): the verifier's chosen source for
//! "is this a root" and "what is the cmx at this output".
//!
//! An oracle answers from chain state the verifier trusts. A full node answers
//! from its own state. A light client answers from a server and MUST either
//! verify tree roots against the block-header chain (ZIP 221) or report the
//! result as *unverified*, never as verified.
//!
//! Provided here: [`ChainOracle`], the trait `verify_chain` consumes, and
//! [`ZebradOracle`], a zebrad (zcashd-compatible) JSON-RPC implementation that
//! shells out to `curl`. With the `lightwalletd` feature, [`LightwalletdOracle`]
//! speaks gRPC to a lightwalletd or Zaino; it reports [`OracleTrust::ServerAsserted`]
//! because it does not check roots against block headers.

use std::cell::RefCell;
use std::collections::HashMap;
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use incrementalmerkletree::frontier::NonEmptyFrontier;
use orchard::note::ExtractedNoteCommitment;
use orchard::tree::{Anchor, MerkleHashOrchard};
use serde_json::{json, Value};
use zcash_client_backend::proto::service::TreeState;

/// Anchors shallower than this are not wrong, they are not yet safe (`WAKE-v1.md` §8).
pub const MIN_DEPTH: u32 = 100;

/// What the oracle says about a claimed anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorStatus {
    /// The root is the Ironwood tree root at the end of the claimed height,
    /// and that height is `depth` blocks below the oracle's tip.
    Known { depth: u32 },
    /// The root is not the tree root at the claimed height.
    Unknown,
}

/// How far an oracle's answers can be trusted (`WAKE-v1.md` §8.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OracleTrust {
    /// The oracle answers from chain state it validated itself (a full node).
    FullNode,
    /// The oracle relays a server's answers and has NOT checked tree roots against
    /// block headers. A verdict built on it MUST be reported as *unverified*.
    ServerAsserted,
}

/// The two questions a verifier asks the chain.
pub trait ChainOracle {
    /// Whether this oracle's answers are self-validated. Defaults to the weaker claim.
    fn trust(&self) -> OracleTrust {
        OracleTrust::ServerAsserted
    }

    /// Is `root` the Ironwood note-commitment-tree root at the end of block `height`,
    /// and how far below the tip is that block?
    fn anchor_at(&self, root: &Anchor, height: u32) -> Result<AnchorStatus>;

    /// The extracted commitment of the Ironwood output at `(txid, action_index)`,
    /// or `None` if the transaction is not mined or has no such Action.
    /// `txid` is in display (byte-reversed) order.
    fn cmx_at(&self, txid: &[u8; 32], action_index: u32) -> Result<Option<ExtractedNoteCommitment>>;
}

/// One Ironwood Action as the node reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IronwoodAction {
    /// The revealed nullifier of the spend. Zebrad encodes it as the field element's
    /// canonical bytes, not reversed (confirmed on mainnet 2026-09-25, chapter 7).
    pub nullifier: [u8; 32],
    /// The extracted commitment of the output, same encoding.
    pub cmx: [u8; 32],
}

/// The Ironwood note-commitment tree at the end of a block.
#[derive(Clone, Debug)]
pub struct IronwoodTreeState {
    pub height: u32,
    /// The tree's root after this block.
    pub root: Anchor,
    /// The tree's frontier after this block, ready for path regeneration.
    pub frontier: NonEmptyFrontier<MerkleHashOrchard>,
}

/// A zebrad (or zcashd-compatible) JSON-RPC endpoint, with a per-height cache of tree states.
#[derive(Debug)]
pub struct ZebradOracle {
    url: String,
    tree_cache: RefCell<HashMap<u32, IronwoodTreeState>>,
}

impl ZebradOracle {
    /// `url` is the RPC listen address, e.g. `http://127.0.0.1:8232`.
    pub fn new(url: impl Into<String>) -> Self {
        ZebradOracle {
            url: url.into(),
            tree_cache: RefCell::new(HashMap::new()),
        }
    }

    /// Raw JSON-RPC call. Returns the `result` value or the node's error.
    pub fn rpc(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let out = Command::new("curl")
            .args([
                "-s",
                "--max-time",
                "60",
                "-u",
                "x:x",
                "-H",
                "content-type: application/json",
                "--data",
                &body.to_string(),
                &self.url,
            ])
            .output()
            .context("run curl")?;
        if !out.status.success() {
            bail!("curl exited with {}", out.status);
        }
        let v: Value = serde_json::from_slice(&out.stdout)
            .with_context(|| format!("parse RPC response to {method}"))?;
        if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
            bail!("{method}: node error {err}");
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| anyhow!("{method}: no result"))
    }

    /// The node's current block height.
    pub fn tip_height(&self) -> Result<u32> {
        let v = self.rpc("getblockcount", json!([]))?;
        v.as_u64()
            .map(|h| h as u32)
            .ok_or_else(|| anyhow!("getblockcount: not a number"))
    }

    /// The Ironwood tree state at the end of block `height` (`z_gettreestate`), cached.
    pub fn ironwood_tree_state(&self, height: u32) -> Result<IronwoodTreeState> {
        if let Some(ts) = self.tree_cache.borrow().get(&height) {
            return Ok(ts.clone());
        }
        let v = self.rpc("z_gettreestate", json!([height.to_string()]))?;
        let iw = v
            .get("ironwood")
            .ok_or_else(|| anyhow!("z_gettreestate: no ironwood field at {height}"))?;
        let final_state = iw
            .pointer("/commitments/finalState")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("z_gettreestate: no ironwood finalState"))?;
        let final_root = iw
            .pointer("/commitments/finalRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("z_gettreestate: no ironwood finalRoot"))?;

        let state = TreeState {
            ironwood_tree: final_state.to_string(),
            ..Default::default()
        };
        let tree = state
            .ironwood_tree()
            .context("parse ironwood finalState as a CommitmentTree")?;
        let root: Anchor = tree.root().into();
        let frontier = tree
            .to_frontier()
            .take()
            .ok_or_else(|| anyhow!("empty ironwood tree at {height}"))?;

        // The node's finalRoot must agree with the parsed tree; if it does not, the
        // encoding we assumed is wrong and no path built from this frontier can verify.
        let reported = decode_hex_32(final_root)?;
        if root.to_bytes() != reported && root.to_bytes() != reversed(reported) {
            bail!("ironwood finalRoot at {height} does not match the parsed tree root");
        }
        let ts = IronwoodTreeState {
            height,
            root,
            frontier,
        };
        self.tree_cache.borrow_mut().insert(height, ts.clone());
        Ok(ts)
    }

    /// The Ironwood Actions of a mined transaction, and the height it was mined at.
    /// `None` if the node does not know the transaction as mined.
    pub fn ironwood_actions(&self, txid_hex: &str) -> Result<Option<(u32, Vec<IronwoodAction>)>> {
        let v = match self.rpc("getrawtransaction", json!([txid_hex, 1])) {
            Ok(v) => v,
            Err(e) if e.to_string().contains("node error") => return Ok(None),
            Err(e) => return Err(e),
        };
        let Some(height) = v.get("height").and_then(Value::as_u64) else {
            return Ok(None);
        };
        let acts = v
            .pointer("/ironwood/actions")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut out = Vec::with_capacity(acts.len());
        for a in &acts {
            let nf = a
                .get("nullifier")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("action without nullifier"))?;
            let cmx = a
                .get("cmx")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("action without cmx"))?;
            out.push(IronwoodAction {
                nullifier: decode_hex_32(nf)?,
                cmx: decode_hex_32(cmx)?,
            });
        }
        Ok(Some((height as u32, out)))
    }
}

impl ChainOracle for ZebradOracle {
    fn trust(&self) -> OracleTrust {
        OracleTrust::FullNode
    }

    fn anchor_at(&self, root: &Anchor, height: u32) -> Result<AnchorStatus> {
        let tip = self.tip_height()?;
        if height > tip {
            return Ok(AnchorStatus::Unknown);
        }
        let ts = self.ironwood_tree_state(height)?;
        if ts.root == *root {
            Ok(AnchorStatus::Known { depth: tip - height })
        } else {
            Ok(AnchorStatus::Unknown)
        }
    }

    fn cmx_at(&self, txid: &[u8; 32], action_index: u32) -> Result<Option<ExtractedNoteCommitment>> {
        let Some((_, actions)) = self.ironwood_actions(&hex(txid))? else {
            return Ok(None);
        };
        let Some(a) = actions.get(action_index as usize) else {
            return Ok(None);
        };
        let cmx: Option<ExtractedNoteCommitment> = ExtractedNoteCommitment::from_bytes(&a.cmx).into();
        Ok(cmx)
    }
}

#[cfg(feature = "lightwalletd")]
pub use crate::oracle_lightwalletd::LightwalletdOracle;

/// Decode exactly 32 bytes of hex.
pub fn decode_hex_32(s: &str) -> Result<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        bail!("expected 64 hex chars, got {}", s.len());
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).context("hex")?;
    }
    Ok(out)
}

/// Lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The same 32 bytes in the other byte order (txids are displayed reversed).
pub fn reversed(mut b: [u8; 32]) -> [u8; 32] {
    b.reverse();
    b
}
