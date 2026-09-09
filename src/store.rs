//! @Name: store
//!
//! @Date: 2026/6/25 17:24
//!
//! @Author: Matrix.Ye
//!
//! @Description: 
//! - BlockStore：保存完整区块。
/// - ChainStore：保存区块索引和 best hash。
/// - UtxoStore：保存当前最佳链的 UTXO 集。
/// - WalletStore：保存钱包密钥和钱包交易。

use crate::block::Block;
use crate::chain::BlockIndex;
use crate::transaction::OutPoint;
use crate::uint256::Uint256;
use crate::utxo::UtxoEntry;


mod schema;
pub mod sqlite;

/// 保存完整区块
pub trait BlockStore {
    type Error;
    fn read_block(&self, hash: Uint256) -> Result<Option<Block>, Self::Error>;
    fn write_block(&mut self, block: &Block) -> Result<(), Self::Error>;
}

/// 保存区块索引和 best hash。
pub trait ChainStore {
    type Error;
    fn load_block_indexes(&self) -> Result<Vec<BlockIndex>, Self::Error>;
    fn load_best_hash(&self) -> Result<Option<Uint256>, Self::Error>;
    fn write_block_index(&mut self, index: &BlockIndex) -> Result<(), Self::Error>;
    fn write_best_hash(&mut self, hash: Uint256) -> Result<(), Self::Error>;
}

/// 保存当前最佳链的 UTXO 集
pub trait UtxoStore {
    type Error;
    fn read_utxo(&self, outpoint: &OutPoint) -> Result<Option<UtxoEntry>, Self::Error>;

    fn write_utxo(&mut self, outpoint: OutPoint, entry: &UtxoEntry) -> Result<(), Self::Error>;

    fn delete_utxo(&mut self, outpoint: &OutPoint) -> Result<(), Self::Error>;

    // fn write_block_undo(&mut self, block_hash: Uint256, undo: &ConnectBlockUndo) -> Result<(), Self::Error>;

    // fn read_block_undo(&self, block_hash: Uint256) -> Result<Option<ConnectBlockUndo>, Self::Error>;

}

/// 保存钱包密钥和钱包交易。
pub trait WalletStore {
    type Error;
    fn write_key();
    fn read_keys();
}
