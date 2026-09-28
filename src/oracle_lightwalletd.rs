//! A lightwalletd / Zaino gRPC oracle (`WAKE-v1.md` §8.1, the light-client case).
//!
//! Behind the `lightwalletd` cargo feature. **Untested against a live endpoint as
//! of 2026-09-25**: the LAN server available then was not reachable from the build machine.
//!
//! This oracle relays what the server says. It does not verify tree roots against
//! the block-header chain (ZIP 221), so it reports [`OracleTrust::ServerAsserted`]
//! and any verdict built on it MUST be shown as *unverified*. A prover who also
//! controls the verifier's server can otherwise supply a fabricated root matching
//! a fabricated proof.

use anyhow::{anyhow, Context, Result};
use orchard::note::ExtractedNoteCommitment;
use orchard::tree::Anchor;
use tokio::runtime::Runtime;
use tonic::transport::Channel;
use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, BlockId, ChainSpec, TxFilter,
};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};

use crate::oracle::{reversed, AnchorStatus, ChainOracle, IronwoodAction, IronwoodTreeState, OracleTrust};

/// A lightwalletd-protocol endpoint, e.g. `http://127.0.0.1:8137`.
pub struct LightwalletdOracle {
    url: String,
    network: Network,
    rt: Runtime,
}

impl std::fmt::Debug for LightwalletdOracle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LightwalletdOracle")
            .field("url", &self.url)
            .field("network", &self.network)
            .finish()
    }
}

impl LightwalletdOracle {
    pub fn new(url: impl Into<String>, network: Network) -> Result<Self> {
        let rt = Runtime::new().context("tokio runtime")?;
        Ok(LightwalletdOracle {
            url: url.into(),
            network,
            rt,
        })
    }

    fn client(&self) -> Result<CompactTxStreamerClient<Channel>> {
        let url = self.url.clone();
        self.rt
            .block_on(CompactTxStreamerClient::connect(url))
            .with_context(|| format!("connect to {}", self.url))
    }

    /// The server's latest block height.
    pub fn tip_height(&self) -> Result<u32> {
        let mut c = self.client()?;
        let id = self
            .rt
            .block_on(c.get_latest_block(ChainSpec {}))
            .context("GetLatestBlock")?
            .into_inner();
        Ok(id.height as u32)
    }

    /// The Ironwood tree state at the end of block `height` (`GetTreeState`).
    pub fn ironwood_tree_state(&self, height: u32) -> Result<IronwoodTreeState> {
        let mut c = self.client()?;
        let ts = self
            .rt
            .block_on(c.get_tree_state(BlockId {
                height: height as u64,
                hash: vec![],
            }))
            .context("GetTreeState")?
            .into_inner();
        let tree = ts
            .ironwood_tree()
            .context("parse ironwood tree from TreeState")?;
        let root: Anchor = tree.root().into();
        let frontier = tree
            .to_frontier()
            .take()
            .ok_or_else(|| anyhow!("empty ironwood tree at {height}"))?;
        Ok(IronwoodTreeState {
            height,
            root,
            frontier,
        })
    }

    /// The Ironwood Actions of a mined transaction (`GetTransaction`, then parsed locally).
    /// `txid` is in display order; lightwalletd wants the internal byte order.
    pub fn ironwood_actions(&self, txid: &[u8; 32]) -> Result<Option<(u32, Vec<IronwoodAction>)>> {
        let mut c = self.client()?;
        let raw = match self.rt.block_on(c.get_transaction(TxFilter {
            block: None,
            index: 0,
            hash: reversed(*txid).to_vec(),
        })) {
            Ok(r) => r.into_inner(),
            Err(status) if status.code() == tonic::Code::NotFound => return Ok(None),
            Err(e) => return Err(anyhow!("GetTransaction: {e}")),
        };
        if raw.height == 0 || raw.data.is_empty() {
            return Ok(None);
        }
        let height = raw.height as u32;
        let branch = BranchId::for_height(&self.network, BlockHeight::from_u32(height));
        let tx = Transaction::read(&raw.data[..], branch).context("parse transaction")?;
        let Some(bundle) = tx.ironwood_bundle() else {
            return Ok(Some((height, Vec::new())));
        };
        let actions = bundle
            .actions()
            .iter()
            .map(|a| IronwoodAction {
                nullifier: a.nullifier().to_bytes(),
                cmx: a.cmx().to_bytes(),
            })
            .collect();
        Ok(Some((height, actions)))
    }
}

impl ChainOracle for LightwalletdOracle {
    fn trust(&self) -> OracleTrust {
        OracleTrust::ServerAsserted
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
        let Some((_, actions)) = self.ironwood_actions(txid)? else {
            return Ok(None);
        };
        let Some(a) = actions.get(action_index as usize) else {
            return Ok(None);
        };
        let cmx: Option<ExtractedNoteCommitment> = ExtractedNoteCommitment::from_bytes(&a.cmx).into();
        Ok(cmx)
    }
}
