//! @Name: node
//!
//! @Date: 2026/7/13 17:34
//!
//! @Author: Matrix.Ye
//!
//! @Description: 全局状态管理

use crate::block::Block;
use crate::chain::BlockTree;
use crate::mempool::Mempool;
use crate::transaction::Transaction;

/// 节点全局状态
pub struct NodeState {
    pub chain: BlockTree,
    pub mempool: Mempool,
    // params:ChainParams,
}

/// 节点事件
pub enum NodeEvent {
    BlockReceived(Block),
    BlockMined(Block),
    TransactionReceived(Transaction),
    TipChanged,
    Shutdown,
}


impl NodeState {}