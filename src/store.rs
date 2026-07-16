//! @Name: store
//!
//! @Date: 2026/6/25 17:24
//!
//! @Author: Matrix.Ye
//!
//! @Description: null

use crate::block::Block;
use crate::chain::BlockIndex;
use crate::uint256::Uint256;

mod schema;
pub mod sqlite;


pub trait BlockStore {
    type Error;
    fn read_block(&self, hash: Uint256) -> Result<Option<Block>, Self::Error>;
    fn write_block(&mut self, block: &Block) -> Result<(), Self::Error>;
}

pub trait ChainStore {
    type Error;
    fn load_block_indexes(&self) -> Result<Vec<BlockIndex>, Self::Error>;
    fn load_best_hash(&self) -> Result<Option<Uint256>, Self::Error>;
    fn write_block_index(&mut self, index: &BlockIndex) -> Result<(), Self::Error>;
    fn write_best_hash(&mut self, hash: Uint256) -> Result<(), Self::Error>;
}

pub trait UtxoStore {
    type Error;
    fn read_utxo();
    fn write_utxo();
    fn spend_utxo();
}

pub trait WalletStore {
    type Error;
    fn write_key();
    fn read_keys();
}
