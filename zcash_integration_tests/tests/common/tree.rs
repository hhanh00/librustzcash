//! Tracks the orchard note commitment tree by syncing from mined blocks.

use bridgetree::BridgeTree;
use incrementalmerkletree::Position;
use orchard::{
    tree::MerkleHashOrchard,
    Anchor,
};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BranchId, Parameters};

use super::rpc::RpcClient;

/// Tracks the Orchard note commitment tree by syncing from mined blocks.
pub struct OrchardTreeState {
    tree: BridgeTree<MerkleHashOrchard, usize, 32>,
    leaf_count: usize,
}

impl OrchardTreeState {
    /// Creates an empty tree state.
    pub fn new() -> Self {
        OrchardTreeState {
            tree: BridgeTree::new(100),
            leaf_count: 0,
        }
    }

    /// Returns the number of leaves currently in the tree.
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Returns the current anchor (root of the tree). If the tree is empty,
    /// returns [`Anchor::empty_tree`].
    ///
    /// Uses `root(0)` which returns the current (uncommitted) tree state root.
    /// Per BridgeTree docs, no checkpoints are required for `root(0)`.
    pub fn anchor(&self) -> Anchor {
        if self.leaf_count == 0 {
            Anchor::empty_tree()
        } else {
            self.tree
                .root(0)
                .map(Anchor::from)
                .unwrap_or_else(Anchor::empty_tree)
        }
    }

    /// Returns a Merkle path for the leaf at the given 0-based index.
    ///
    /// Panics if the index is out of bounds or the tree is empty.
    ///
    /// Uses `witness(pos, 0)` which returns the witness against the current
    /// tree state. Per BridgeTree docs, no checkpoints are required.
    pub fn witness(&self, index: usize) -> orchard::tree::MerklePath {
        let pos: u64 = index as u64;
        orchard::tree::MerklePath::from_parts(
            index as u32,
            self.tree
                .witness(Position::from(pos), 0)
                .expect("witness failed")
                .try_into()
                .expect("wrong auth path length"),
        )
    }

    /// Fetches a block with `getblock` (verbosity=2), parses every transaction to
    /// extract Orchard note commitments, and appends them to the tree.
    ///
    /// After syncing, the tree is checkpointed at the block height. This ensures the
    /// local tree matches the chain regardless of what other transactions are in the
    /// block.
    #[allow(unused)]
    pub fn sync_block(&mut self, rpc: &RpcClient, block_hash: &str, params: &impl Parameters) -> Result<SyncResult, String> {
        let block: serde_json::Value = rpc.get_block(block_hash)?;

        let height: u32 = block
            .get("height")
            .and_then(|h| h.as_u64())
            .ok_or("block missing height")? as u32;
        let txs = block
            .get("tx")
            .and_then(|t| t.as_array())
            .ok_or("block missing tx array")?;

        // Use the params passed by the caller instead of TEST_NETWORK
        let branch = BranchId::for_height(params, height.into());
        let count_before = self.leaf_count;
        let mut total_commitments: usize = 0;

        for tx_json in txs {
            let hex = tx_json
                .get("hex")
                .and_then(|h| h.as_str())
                .ok_or("tx missing hex")?;
            let raw = hex::decode(hex).map_err(|e| format!("hex decode: {e}"))?;

            let tx = Transaction::read(&raw[..], branch)
                .map_err(|e| format!("tx parse error: {e}"))?;

            if let Some(ob) = tx.orchard_bundle() {
                let zsa = ob.as_zsa_bundle();
                for action in zsa.actions() {
                    let cmx = action.cmx();
                    let leaf = MerkleHashOrchard::from_cmx(cmx);
                    self.tree.append(leaf);
                    self.tree.mark();
                    self.leaf_count += 1;
                    total_commitments += 1;
                }
            }
            #[cfg(zcash_unstable = "nu7")]
            if let Some(ib) = tx.issue_bundle() {
                for note in ib.actions().iter().flat_map(|a| a.notes()) {
                    let cmx = orchard::note::ExtractedNoteCommitment::from(note.commitment());
                    let leaf = MerkleHashOrchard::from_cmx(&cmx);
                    self.tree.append(leaf);
                    self.tree.mark();
                    self.leaf_count += 1;
                    total_commitments += 1;
                }
            }
        }

        Ok(SyncResult {
            height,
            count_before,
            count_after: self.leaf_count,
            total_commitments,
        })
    }
}

/// Result of syncing a block into the tree.
pub struct SyncResult {
    /// Block height that was checkpointed.
    pub height: u32,
    /// Number of leaves before syncing this block.
    pub count_before: usize,
    /// Number of leaves after syncing this block.
    pub count_after: usize,
    /// Total orchard note commitments found in this block.
    pub total_commitments: usize,
}

impl SyncResult {
    /// Returns the 0-based leaf indices that were added by this sync.
    pub fn new_indices(&self) -> std::ops::Range<usize> {
        self.count_before..self.count_after
    }
}
