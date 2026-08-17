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

use crate::block::{Block, BlockError};
use crate::mempool::MempoolError;
use crate::node::NodeState;
use crate::pow::{get_next_work_required, PowError};
use crate::script::builder::StandardScript;
use crate::script::error::ScriptError;
use crate::transaction::Transaction;
use crate::utils::get_adjusted_time;
use crate::wallet::key::PubKey;
use std::cmp::max;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MiningError {
    #[error("block error: {0}")]
    BlockError(#[from] BlockError),

    #[error("pow error {0}")]
    PowError(#[from] PowError),

    #[error("script error {0}")]
    ScriptError(#[from] ScriptError),

    #[error("mempool error {0}")]
    MempoolError(#[from] MempoolError),

    #[error("unknown block index")]
    UnknownBlockIndex,

    #[error("invalid transaction")]
    InvalidTransaction,

    #[error("invalid coinbase")]
    InvalidCoinbase { msg: String },

    #[error("best index hash not found")]
    BestIndexNotFound,

    #[error("invalid chain params: {msg}")]
    InvalidChainParams { msg: String },

    #[error("block value overflow")]
    BlockValueOverflow,

    #[error("block timestamp overflow")]
    InvalidTime,
}

/// 创建一个基于当前最佳链 tip 的候选区块。
///
/// 对应原版 `CreateNewBlock` 的核心流程：先放入 coinbase，再收集 mempool 交易，
/// 最后根据交易集合和前序区块索引初始化区块头字段。
pub fn create_new_block(state: &NodeState, pub_key: PubKey) -> Result<Block, MiningError> {
    let best_index = state
        .chain
        .best_index()
        .ok_or(MiningError::BestIndexNotFound)?;
    let next_height = best_index.height + 1;
    let block_time = get_block_time(state)?;

    let (txs, total_fees) = state.mempool.collect_for_block(next_height, block_time, 1000, 100)?;

    let mut pblock = Block::new();
    let mut coinbase = Transaction::new_coinbase();
    coinbase.vout[0].script_pubkey = StandardScript::p2pk(pub_key)?;

    pblock.push_tx(coinbase);
    pblock.push_txs(txs);
    pblock.update_coinbase_value(get_block_value(&state, total_fees, next_height)?)?;
    pblock.set_prev_block(best_index.hash());
    pblock.set_merkle_root(pblock.get_merkle_root());
    pblock.set_time(block_time);
    pblock.set_bits(get_nbits(state)?);
    pblock.set_nonce(0);
    Ok(pblock)
}

/// 计算区块价值：区块补贴 + 当前候选区块打包交易产生的手续费。
fn get_block_value(state: &NodeState, total_fees: u64, height: u32) -> Result<u64, MiningError> {
    // 减半周期无法为0
    if state.params.subsidy_halving_interval == 0 {
        return Err(MiningError::InvalidChainParams {
            msg: "subsidy halving interval must be greater than zero".to_string(),
        });
    }
    // 计算衰减次数
    let halvings = height as u64 / state.params.subsidy_halving_interval;
    // 计算当前补贴
    let subsidy = state
        .params
        .subsidy_initial
        .checked_shr(halvings as u32)
        .unwrap_or(0);
    // 价值=区块补贴+手续费累计
    let value = total_fees
        .checked_add(subsidy)
        .ok_or(MiningError::BlockValueOverflow);
    value
}

/// 当前阶段先沿用父区块难度，后续替换为 `pow::get_next_work_required`。
fn get_nbits(state: &NodeState) -> Result<u32, MiningError> {
    // let x = &state.chain;
    // let y = state.chain.best_index().ok_or(MiningError::BestIndexNotFound)?;
    // let z = &state.params;

    let nbits = get_next_work_required(
        &state.chain,
        state.chain.best_index().ok_or(MiningError::BestIndexNotFound)?,
        &state.params,
    )?;
    Ok(nbits)
}

/// 当前阶段使用 `max(GetMedianTimePast() + 1, now)` 近似原版 `max(GetMedianTimePast()+1, GetAdjustedTime())`。
/// - `GetMedianTimePast` 获取最佳链上的最近的11个区块的时间中位数，减少单个异常时间戳的影响
/// - `GetAdjustedTime` 是获取系统自适应时间，它不是单纯的本机时间，而是本机当前时间+根据其他节点时间样本计算出的 nTimeOffset，因为逻辑繁琐一下子写不完，暂时先用本机当前时间代替
fn get_block_time(state: &NodeState) -> Result<u32, MiningError> {
    let median_time = state.chain.get_median_time_past().ok_or(MiningError::InvalidTime)?;
    let adjusted_time = get_adjusted_time();
    let t = max(median_time.saturating_add(1), adjusted_time);
    Ok(t)
}

fn updata_extra_nonce(_block: Block, _height: u32) {
    todo!();
}
// 拓展nonce搜索空间
fn increment_extra_nonce() {
    todo!()
}
