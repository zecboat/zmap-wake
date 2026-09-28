//! Received notes and their witnesses from a wallet **copy**.
//!
//! Shared by the chapter 7 mainnet test (a holder's wallet) and the chapter 9
//! issuer tool (the mint wallet). Never a live wallet: every path goes through
//! [`crate::wallet_path::guard_not_live`].

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use incrementalmerkletree::Position;
use orchard::keys::{Diversifier, FullViewingKey, Scope};
use orchard::note::{ExtractedNoteCommitment, Note, NoteVersion, RandomSeed, Rho};
use orchard::value::NoteValue;
use rusqlite::OptionalExtension;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::{BlockHeight, Network};

use crate::oracle::{reversed, IronwoodTreeState};
use crate::wallet_path::{ironwood_paths_at_height, open_wallet_copy_sql};
use crate::witness::Witness;

/// An Ironwood note a wallet received, reconstructed from its database.
#[derive(Clone, Debug)]
pub struct ReceivedNote {
    pub row_id: i64,
    pub txid_display: [u8; 32],
    pub mined_height: u32,
    pub action_index: u32,
    pub value: u64,
    pub is_change: bool,
    pub note: Note,
    /// The Orchard full viewing key of the receiving account (Ironwood shares it).
    pub fvk: FullViewingKey,
    pub position: Option<u64>,
    pub stored_nf: Option<[u8; 32]>,
    /// The memo bytes as the wallet stored them (`None` if not decrypted; a lone
    /// `0xf6` is an empty memo).
    pub memo: Option<Vec<u8>>,
}

impl ReceivedNote {
    /// The ZMAP `asset_id` in this note's memo, if the memo is a ZMAP JSON memo.
    pub fn zmap_asset_id(&self) -> Option<String> {
        let m = self.memo.as_ref()?;
        let end = m.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(0);
        let v: serde_json::Value = serde_json::from_slice(&m[..end]).ok()?;
        v.get("asset_id")?.as_str().map(str::to_string)
    }

    pub fn cmx(&self) -> ExtractedNoteCommitment {
        ExtractedNoteCommitment::from(self.note.commitment())
    }
}

/// Every Ironwood note the wallet received in transaction `txid_display`.
///
/// Transactions store the txid in internal byte order; receipts and explorers
/// show it reversed. Both are tried.
pub fn received_notes_in_tx(
    wallet_path: &Path,
    network: Network,
    txid_display: &[u8; 32],
) -> Result<Vec<ReceivedNote>> {
    let conn = open_wallet_copy_sql(wallet_path)?;
    received_notes_in_tx_conn(&conn, network, txid_display)
}

/// [`received_notes_in_tx`] over an already-open connection. The wallet itself
/// (chapter 8) calls this on its own database; the path guard is the caller's.
pub fn received_notes_in_tx_conn(
    conn: &rusqlite::Connection,
    network: Network,
    txid_display: &[u8; 32],
) -> Result<Vec<ReceivedNote>> {
    let lookup = |txid: &[u8; 32]| -> Result<Option<(i64, Option<u32>)>> {
        conn.query_row(
            "SELECT id_tx, mined_height FROM transactions WHERE txid = ?1",
            [txid.as_slice()],
            |r| Ok((r.get(0)?, r.get::<_, Option<u32>>(1)?)),
        )
        .optional()
        .context("query transactions")
    };
    let (id_tx, mined_height) = match lookup(&reversed(*txid_display))? {
        Some(x) => x,
        None => lookup(txid_display)?.ok_or_else(|| anyhow!("transaction not in this wallet"))?,
    };
    let mined_height = mined_height.ok_or_else(|| {
        anyhow!("the wallet has this transaction but has not seen it mined yet; sync the wallet and copy it again")
    })?;

    let mut stmt = conn.prepare(
        "SELECT n.id, n.action_index, n.diversifier, n.value, n.rho, n.rseed, n.nf,
                n.commitment_tree_position, n.recipient_key_scope, n.note_version, n.is_change,
                a.ufvk, n.memo
           FROM ironwood_received_notes n JOIN accounts a ON a.id = n.account_id
          WHERE n.transaction_id = ?1
          ORDER BY n.action_index",
    )?;
    let rows = stmt.query_map([id_tx], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, u32>(1)?,
            r.get::<_, Vec<u8>>(2)?,
            r.get::<_, i64>(3)? as u64,
            r.get::<_, Vec<u8>>(4)?,
            r.get::<_, Vec<u8>>(5)?,
            r.get::<_, Option<Vec<u8>>>(6)?,
            r.get::<_, Option<i64>>(7)?.map(|p| p as u64),
            r.get::<_, Option<i64>>(8)?,
            r.get::<_, i64>(9)?,
            r.get::<_, i64>(10)? != 0,
            r.get::<_, String>(11)?,
            r.get::<_, Option<Vec<u8>>>(12)?,
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (row_id, action_index, d, value, rho, rseed, nf, position, scope, version, is_change, ufvk, memo) =
            row?;
        let ufvk = UnifiedFullViewingKey::decode(&network, &ufvk)
            .map_err(|e| anyhow!("decode UFVK: {e}"))?;
        // Ironwood shares the Orchard receiver and keys (zcash_keys address.rs:447).
        let fvk = ufvk
            .orchard()
            .ok_or_else(|| anyhow!("UFVK has no Orchard component"))?
            .clone();
        let scope = match scope {
            Some(1) => Scope::Internal,
            _ => Scope::External,
        };
        let d: [u8; 11] = d.as_slice().try_into().context("11-byte diversifier")?;
        let recipient = fvk.address(Diversifier::from_bytes(d), scope);
        let rho: [u8; 32] = rho.as_slice().try_into().context("32-byte rho")?;
        let rho = Option::<Rho>::from(Rho::from_bytes(&rho)).ok_or_else(|| anyhow!("non-canonical rho"))?;
        let rseed: [u8; 32] = rseed.as_slice().try_into().context("32-byte rseed")?;
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(rseed, &rho))
            .ok_or_else(|| anyhow!("rseed does not match rho"))?;
        let version = match version {
            2 => NoteVersion::V2,
            3 => NoteVersion::V3,
            v => return Err(anyhow!("unexpected note_version {v}")),
        };
        let note = Option::<Note>::from(Note::from_parts(
            recipient,
            NoteValue::from_raw(value),
            rho,
            rseed,
            version,
        ))
        .ok_or_else(|| anyhow!("note does not reconstruct"))?;
        let stored_nf = match nf {
            Some(b) => Some(b.as_slice().try_into().context("32-byte nf")?),
            None => None,
        };
        out.push(ReceivedNote {
            row_id,
            txid_display: *txid_display,
            mined_height,
            action_index,
            value,
            is_change,
            note,
            fvk,
            position,
            stored_nf,
            memo,
        });
    }
    Ok(out)
}

/// The spent notes of a wallet that were consumed by transaction `txid_display`,
/// with their nullifiers: what the sender put into that transaction.
pub fn spent_notes_in_tx(
    wallet_path: &Path,
    network: Network,
    txid_display: &[u8; 32],
) -> Result<Vec<ReceivedNote>> {
    let conn = open_wallet_copy_sql(wallet_path)?;
    let internal = reversed(*txid_display);
    let mut stmt = conn.prepare(
        "SELECT s.ironwood_received_note_id, rt.txid
           FROM ironwood_received_note_spends s
           JOIN transactions t ON t.id_tx = s.transaction_id
           JOIN ironwood_received_notes n ON n.id = s.ironwood_received_note_id
           JOIN transactions rt ON rt.id_tx = n.transaction_id
          WHERE t.txid = ?1 OR t.txid = ?2",
    )?;
    let rows: Vec<(i64, Vec<u8>)> = stmt
        .query_map([internal.as_slice(), txid_display.as_slice()], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    drop(stmt);
    drop(conn);
    let mut out = Vec::new();
    for (row_id, received_txid) in rows {
        let received: [u8; 32] = received_txid.as_slice().try_into().context("32-byte txid")?;
        let notes = received_notes_in_tx(wallet_path, network, &reversed(received))?;
        out.extend(notes.into_iter().filter(|n| n.row_id == row_id));
    }
    Ok(out)
}

/// The transactions the wallet recorded as spending note `row_id`, as
/// `(txid_display, mined_height)`. A row with no mined height is a spend the
/// wallet built but never saw mined.
pub fn spent_in(wallet_path: &Path, row_id: i64) -> Result<Vec<([u8; 32], Option<u32>)>> {
    let conn = open_wallet_copy_sql(wallet_path)?;
    let mut stmt = conn.prepare(
        "SELECT t.txid, t.mined_height FROM ironwood_received_note_spends s
           JOIN transactions t ON t.id_tx = s.transaction_id
          WHERE s.ironwood_received_note_id = ?1",
    )?;
    let rows = stmt.query_map([row_id], |r| {
        Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Option<u32>>(1)?))
    })?;
    let mut out = Vec::new();
    for r in rows {
        let (txid, h) = r?;
        let txid: [u8; 32] = txid.as_slice().try_into().context("32-byte txid")?;
        out.push((reversed(txid), h));
    }
    Ok(out)
}

/// The witness for `n` with its authentication path rebuilt from the wallet's
/// shards against the tree state `ts` (normally the state at `n.mined_height`
/// or any later height the oracle can vouch for).
pub fn witness_at<P: zcash_protocol::consensus::Parameters>(
    db: &zcash_client_sqlite::WalletDb<rusqlite::Connection, P, zcash_client_sqlite::util::SystemClock, rand::rngs::OsRng>,
    n: &ReceivedNote,
    ts: &IronwoodTreeState,
) -> Result<Witness> {
    let position = Position::from(n.position.ok_or_else(|| anyhow!("note has no tree position"))?);
    let paths = ironwood_paths_at_height(
        db,
        &[position],
        ts.frontier.clone(),
        BlockHeight::from_u32(ts.height),
    )?;
    let w = Witness::from_note(&n.note, &n.fvk, &paths[0]);
    let anchor = Option::<orchard::tree::Anchor>::from(w.anchor())
        .ok_or_else(|| anyhow!("witness has no anchor"))?;
    if anchor != ts.root {
        return Err(anyhow!(
            "path from the wallet's shards does not reach the oracle's root at {}",
            ts.height
        ));
    }
    Ok(w)
}
