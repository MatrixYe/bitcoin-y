//! @Name: mining
//!
//! @Date: 2026/7/13 17:11
//!
//! @Author: Matrix.Ye
//!
//! @Description: null!
//! ```text
//! GenerateBitcoins()
//!   -> ThreadBitcoinMiner()
//!   -> BitcoinMiner()
//!   -> CreateNewBlock()
//!   -> IncrementExtraNonce()
//!   -> FormatHashBuffers()
//!   -> ScanHash_CryptoPP() / ScanHash_4WaySSE2()
//!   -> CheckWork()
//!   -> ProcessBlock()
//!   -> AcceptBlock()
//!   -> AddToBlockIndex()
//!   -> SetBestChain()
//! ```
use crate::block::Block;
use crate::node::NodeState;
use crate::script::builder::StandardScript;
use crate::transaction::Transaction;
use crate::wallet::key::PubKey;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MiningError {
    #[error("unknown block index")]
    UnknownBlockIndex,

    #[error("invalid transaction")]
    InvalidTransaction,

    #[error("invalid coinbase")]
    InvalidCoinbase { msg: String },

    #[error("best index hash not found")]
    BestIndexNotFound,

}

fn create_new_block<S>(state: &NodeState<S>, pub_key: PubKey) -> Result<Block, MiningError> {

    // 获取当前最佳链的最新高度
    let height = state.chain.best_height().ok_or(MiningError::BestIndexNotFound)?;
    // 创建待选区块
    let mut pblock = Block::new();

    // 创建一coinbase交易
    let mut coinbase = Transaction::new_coinbase();
    let script_pubkey = StandardScript::p2pk(pub_key).map_err(|e| MiningError::InvalidCoinbase { msg: e.to_string() })?;
    coinbase.vout[0].script_pubkey = script_pubkey;
    // Add our coinbase tx as first transaction
    pblock.push_tx(coinbase);

    // Collect memory pool transactions into the block
    let (txs, fee) = state.mempool.collect_for_block();
    let subsidy = (state.params.subsidy_initial >> height) / state.params.subsidy_halving_interval;
    let block_value = fee + subsidy;

    pblock.update_coinbase_value(block_value).map_err(|e| MiningError::InvalidCoinbase { msg: e.to_string() })?;

    // 初始化区块头数据
    pblock.set_prev_block(state.chain.best_hash().ok_or(MiningError::BestIndexNotFound)?); // 前序区块哈希
    pblock.set_merkle_root(pblock.build_merkle_root()); // 新区块默克尔树根
    pblock.set_time(0); //todo 填充新区块时间
    pblock.set_bits(0); //todo 填充新区块难度压缩值
    pblock.set_nonce(0); // 填充nonce搜索起始点，默认为0
    Ok(pblock)
}

fn updata_extra_nonce(block: Block, height: u32) {
    todo!();
}
// 拓展nonce搜索空间
fn increment_extra_nonce() {
    unimplemented!();
}
