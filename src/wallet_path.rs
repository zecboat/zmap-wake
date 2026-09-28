//! Merkle paths at a past anchor, from a **copy** of a wallet database.
//!
//! A Wake proof needs the note's authentication path at `anchor_j`. The
//! production rule is to prove before spending, while the wallet still holds
//! the live witness. For a note already spent (a retroactive proof, as in
//! chapter 7) the path must be rebuilt at a past height. Upstream
//! `zcash_client_sqlite 0.22.0-rc.4` can do that from the wallet's shard store:
//! `WalletDb::generate_ironwood_witnesses_at_historical_height`
//! (`lib.rs:3377`), the same call Zcash Coin Voting makes
//! (`zcash_voting/src/witness.rs:198`). This resolved `zecboat_wake_circuit.md`
//! P0 answer 4 on 2026-09-24.
//!
//! Separation rule (owner, 2026-09-24): this module opens databases
//! **read-only** and is only ever pointed at a copy. It never writes.

use anyhow::{anyhow, Context, Result};
use incrementalmerkletree::frontier::NonEmptyFrontier;
use incrementalmerkletree::Position;
use orchard::tree::{MerkleHashOrchard, MerklePath};
use rand::rngs::OsRng;
use rusqlite::{Connection, OpenFlags};
use std::path::Path;
use zcash_client_sqlite::util::SystemClock;
use zcash_client_sqlite::WalletDb;
use zcash_protocol::consensus::{BlockHeight, Network};

/// A wallet database opened for reading paths. Same type parameters Zecboat uses.
pub type WalletCopy = WalletDb<Connection, Network, SystemClock, OsRng>;

/// Open a **copy** of a wallet database read-only.
///
/// Refuses to open anything under a directory named `.AppVault`, the live
/// wallet's home, so a typo cannot violate the separation rule.
pub fn open_wallet_copy(path: impl AsRef<Path>, network: Network) -> Result<WalletCopy> {
    let path = path.as_ref();
    guard_not_live(path)?;
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("open {} read-only", path.display()))?;
    rusqlite::vtab::array::load_module(&conn).context("load rusqlite array module")?;
    Ok(WalletDb::from_connection(conn, network, SystemClock, OsRng))
}

/// The separation rule as a check: any path with a `.AppVault` component is the
/// live wallet's home and is refused.
pub fn guard_not_live(path: &Path) -> Result<()> {
    if path
        .components()
        .any(|c| c.as_os_str().to_string_lossy() == ".AppVault")
    {
        return Err(anyhow!(
            "refusing to open {}: that is under the live wallet's home; copy it first",
            path.display()
        ));
    }
    Ok(())
}

/// A plain read-only SQL connection to a wallet copy, for queries the
/// `WalletDb` API does not expose.
pub fn open_wallet_copy_sql(path: impl AsRef<Path>) -> Result<Connection> {
    let path = path.as_ref();
    guard_not_live(path)?;
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("open {} read-only", path.display()))?;
    Ok(conn)
}

/// Authentication paths for Ironwood notes at `positions`, as they stood at
/// `height`, given the tree's frontier at that height.
///
/// The frontier comes from outside the wallet (a node's `z_gettreestate`, or a
/// checkpoint the wallet retained). The function rebuilds each path from the
/// wallet's shard store and fails if the shards no longer cover the position.
/// The returned paths are orchard's own type, ready for [`crate::Witness`].
///
/// Generic over the network type so the live wallet's own handle
/// (`WalletDb<_, MainNetwork, _, _>`, chapter 8) can call it as well as a copy.
pub fn ironwood_paths_at_height<P: zcash_protocol::consensus::Parameters>(
    db: &WalletDb<Connection, P, SystemClock, OsRng>,
    positions: &[Position],
    frontier_at_height: NonEmptyFrontier<MerkleHashOrchard>,
    height: BlockHeight,
) -> Result<Vec<MerklePath>> {
    let paths = db
        .generate_ironwood_witnesses_at_historical_height(positions, frontier_at_height, height)
        .map_err(|e| anyhow!("generate_ironwood_witnesses_at_historical_height: {e}"))?;
    if paths.len() != positions.len() {
        return Err(anyhow!(
            "asked for {} paths, got {}",
            positions.len(),
            paths.len()
        ));
    }
    Ok(paths.into_iter().map(MerklePath::from).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Witness;
    use incrementalmerkletree::frontier::Frontier;
    use incrementalmerkletree::Retention;
    use orchard::keys::FullViewingKey;
    use orchard::note::{ExtractedNoteCommitment, Note, NoteVersion};
    use orchard::tree::Anchor;
    use zcash_client_backend::data_api::WalletCommitmentTrees;
    use zcash_client_sqlite::wallet::init::WalletMigrator;
    use zcash_client_sqlite::error::SqliteClientError;

    const DEPTH: u8 = orchard::NOTE_COMMITMENT_TREE_DEPTH as u8;

    fn fresh_db() -> WalletCopy {
        let conn = Connection::open_in_memory().unwrap();
        rusqlite::vtab::array::load_module(&conn).unwrap();
        let mut db = WalletDb::from_connection(conn, Network::MainNetwork, SystemClock, OsRng);
        WalletMigrator::new().init_or_migrate(&mut db).expect("init wallet db");
        db
    }

    fn real_notes(n: usize) -> Vec<(FullViewingKey, Note)> {
        (0..n)
            .map(|_| {
                let (_sk, fvk, note) = Note::dummy(&mut OsRng, None, NoteVersion::V3);
                (fvk, note)
            })
            .collect()
    }

    /// Seed an Ironwood tree with real note commitments, checkpoint at `height`,
    /// then keep appending and checkpoint later, exactly as a wallet that has
    /// synced past the spend would look. Returns the frontier at `height`.
    fn seed(
        db: &mut WalletCopy,
        notes: &[(FullViewingKey, Note)],
        marked: &[usize],
        height: u32,
        later: u32,
    ) -> Frontier<MerkleHashOrchard, DEPTH> {
        let mut frontier = Frontier::empty();
        db.with_ironwood_tree_mut::<_, _, SqliteClientError>(|tree| {
            for (i, (_, note)) in notes.iter().enumerate() {
                let leaf =
                    MerkleHashOrchard::from_cmx(&ExtractedNoteCommitment::from(note.commitment()));
                let retention = if marked.contains(&i) {
                    Retention::Marked
                } else {
                    Retention::Ephemeral
                };
                tree.append(leaf, retention)?;
                frontier.append(leaf);
            }
            tree.checkpoint(BlockHeight::from_u32(height))?;
            for (_, note) in real_notes(5) {
                let leaf =
                    MerkleHashOrchard::from_cmx(&ExtractedNoteCommitment::from(note.commitment()));
                tree.append(leaf, Retention::Ephemeral)?;
            }
            tree.checkpoint(BlockHeight::from_u32(later))?;
            Ok(())
        })
        .expect("seed ironwood tree");
        frontier
    }

    /// A path rebuilt at the checkpointed height leads, from the note's own cmx,
    /// to the root the tree had at that height, and the Witness agrees.
    #[test]
    fn historical_path_reaches_the_historical_root() {
        let notes = real_notes(6);
        let marked = [1usize, 4];
        let mut db = fresh_db();
        let frontier = seed(&mut db, &notes, &marked, 1_000, 1_010);
        let root_at_height: Anchor = frontier.root().into();
        let nonempty = frontier.take().expect("non-empty frontier");

        let positions: Vec<Position> = marked.iter().map(|&i| Position::from(i as u64)).collect();
        let paths =
            ironwood_paths_at_height(&db, &positions, nonempty, BlockHeight::from_u32(1_000))
                .expect("paths");
        assert_eq!(paths.len(), 2);

        for (path, &i) in paths.iter().zip(marked.iter()) {
            let (fvk, note) = &notes[i];
            assert_eq!(path.position(), i as u32);
            let w = Witness::from_note(note, fvk, path);
            assert_eq!(w.anchor().unwrap(), root_at_height, "note {i}");
        }
    }

    /// A position the wallet never marked has no retained path: the call must
    /// fail, not fabricate one.
    #[test]
    fn unmarked_position_is_an_error() {
        let notes = real_notes(6);
        let mut db = fresh_db();
        let frontier = seed(&mut db, &notes, &[1], 1_000, 1_010);
        let nonempty = frontier.take().unwrap();
        let r = ironwood_paths_at_height(
            &db,
            &[Position::from(3)],
            nonempty,
            BlockHeight::from_u32(1_000),
        );
        assert!(r.is_err(), "got a path for an unmarked leaf: {r:?}");
    }

    /// The separation guard: a path under `.AppVault` is refused before any I/O.
    #[test]
    fn refuses_live_wallet_home() {
        let r = open_wallet_copy("/home/nobody/.AppVault/data/wallet.db", Network::MainNetwork);
        assert!(r.is_err());
    }
}
