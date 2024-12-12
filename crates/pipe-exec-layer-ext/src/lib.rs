use alloy_primitives::B256;
use once_cell::sync::OnceCell;
use reth_primitives::BlockWithSenders;
use std::sync::Mutex;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockId(pub B256);

/// Called by Coordinator
#[derive(Debug)]
pub struct PipeExecLayerApi {
    ordered_block_tx: UnboundedSender<(BlockId, BlockWithSenders)>,
    executed_block_hash_rx: UnboundedReceiver<(BlockId, B256 /* block hash */)>,
    ready_to_get_payload_rx: UnboundedReceiver<BlockId>,
    ready_to_new_payload_rx: UnboundedReceiver<BlockId>,
}

impl PipeExecLayerApi {
    /// Push ordered block to EL for execution.
    /// Returns `None` if the channel has been closed.
    pub fn push_ordered_block(&self, block_id: BlockId, block: BlockWithSenders) -> Option<()> {
        self.ordered_block_tx.send((block_id, block)).ok()
    }

    /// Pull executed block hash from EL for verification.
    /// Returns `None` if the channel has been closed.
    pub async fn pull_executed_block_hash(&mut self, block_id: BlockId) -> Option<B256> {
        let (id, hash) = self.executed_block_hash_rx.recv().await?;
        assert_eq!(block_id, id);
        Some(hash)
    }

    /// Wait until EL is ready to process get_payload.
    /// Returns `None` if the channel has been closed.
    pub async fn ready_to_get_payload(&mut self, block_id: BlockId) -> Option<()> {
        let id = self.ready_to_get_payload_rx.recv().await?;
        assert_eq!(block_id, id);
        Some(())
    }

    /// Wait until EL is ready to process new_payload.
    /// Returns `None` if the channel has been closed.
    pub async fn ready_to_new_payload(&mut self, block_id: BlockId) -> Option<()> {
        let id = self.ready_to_new_payload_rx.recv().await?;
        assert_eq!(block_id, id);
        Some(())
    }
}

/// Owned by EL
#[derive(Debug)]
pub struct PipeExecLayerExt {
    /// Receive ordered block from Coordinator
    ordered_block_rx: Mutex<UnboundedReceiver<(BlockId, BlockWithSenders)>>,
    /// Send execited block hash to Coordinator
    executed_block_hash_tx: UnboundedSender<(BlockId, B256)>,
    /// Send ready to process get_payload signal to Coordinator
    ready_to_get_payload_tx: UnboundedSender<BlockId>,
    /// Send ready to process new_payload signal to Coordinator
    ready_to_new_payload_tx: UnboundedSender<BlockId>,
}

impl PipeExecLayerExt {
    /// Pull next ordered block from Coordinator.
    /// Returns `None` if the channel has been closed.
    pub fn pull_ordered_block(&self) -> Option<(BlockId, BlockWithSenders)> {
        self.ordered_block_rx.lock().unwrap().blocking_recv()
    }

    /// Push execited block hash to Coordinator.
    /// Returns `None` if the channel has been closed.
    pub fn push_executed_block_hash(&self, block_id: BlockId, block_hash: B256) -> Option<()> {
        self.executed_block_hash_tx.send((block_id, block_hash)).ok()
    }

    /// Send ready to process get_payload signal to Coordinator.
    /// Returns `None` if the channel has been closed.
    pub fn send_ready_to_get_payload(&self, block_id: BlockId) -> Option<()> {
        self.ready_to_get_payload_tx.send(block_id).ok()
    }

    /// Send ready to process new_payload signal to Coordinator.
    /// Returns `None` if the channel has been closed.
    pub fn send_ready_to_new_payload(&self, block_id: BlockId) -> Option<()> {
        self.ready_to_new_payload_tx.send(block_id).ok()
    }
}

pub static PIPE_EXEC_LAYER_EXT: OnceCell<PipeExecLayerExt> = OnceCell::new();

pub fn new_pipe_exec_layer_api() -> PipeExecLayerApi {
    let (ordered_block_tx, ordered_block_rx) = tokio::sync::mpsc::unbounded_channel();
    let (executed_block_hash_tx, executed_block_hash_rx) = tokio::sync::mpsc::unbounded_channel();
    let (ready_to_get_payload_tx, ready_to_get_payload_rx) = tokio::sync::mpsc::unbounded_channel();
    let (ready_to_new_payload_tx, ready_to_new_payload_rx) = tokio::sync::mpsc::unbounded_channel();

    let _ = PIPE_EXEC_LAYER_EXT.get_or_init(|| PipeExecLayerExt {
        ordered_block_rx: Mutex::new(ordered_block_rx),
        executed_block_hash_tx,
        ready_to_get_payload_tx,
        ready_to_new_payload_tx,
    });

    PipeExecLayerApi {
        ordered_block_tx,
        executed_block_hash_rx,
        ready_to_get_payload_rx,
        ready_to_new_payload_rx,
    }
}
