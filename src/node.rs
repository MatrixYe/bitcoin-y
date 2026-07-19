//! @Name: node
//!
//! @Date: 2026/7/13 17:34
//!
//! @Author: Matrix.Ye
//!
//! @Description: 全局状态管理
//! - BlockTree 保存区块头索引，不保存完整区块体
//! - MemPool 保存有限数量的待确认交易
//! - Store 保存完整区块、交易、UTXO、钱包数据
//! - ChainParams 保存 pow limit、创世块、减半周期、目标间隔

use crate::block::Block;
use crate::chain::BlockTree;
use crate::mempool::Mempool;
use crate::parms::ChainParams;
use crate::transaction::Transaction;
/// 节点全局状态
pub struct NodeState {
    pub chain: BlockTree,
    pub mempool: Mempool,
    pub params: ChainParams,
    // pub store: S,
}

/// 节点事件
pub enum NodeEvent {
    BlockReceived(Block),
    BlockMined(Block),
    TransactionReceived(Transaction),
    TipChanged,
    Shutdown,
}

impl NodeState {
    pub fn new(chain: BlockTree, mempool: Mempool, params: ChainParams) -> Self {
        Self {
            chain,
            mempool,
            params,
        }
    }
}
