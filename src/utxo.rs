//! @Name: utxo
//!
//! @Date: 2026/8/18 18:53
//!
//! @Author: Matrix.Ye
//!
//! @Description: 维护当前最佳链对应的未花费输出集合。

use crate::transaction::{OutPoint, Transaction, TxOut};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UtxoError {
    #[error("missing unspent output: {outpoint:?}")]
    MissingOutput { outpoint: OutPoint }, //输入引用的 OutPoint 不在 UTXO 集中

    #[error("coinbase output is not mature: {outpoint:?}, depth={depth}")]
    CoinbaseNotMature { outpoint: OutPoint, depth: u32 }, //花费 coinbase 但确认数不足。

    #[error("UTXO value overflow")]
    ValueOverflow, //输入或输出金额累计溢出。

    #[error("UTXO value underflow")]
    ValueUnderflow, //输入金额小于输出金额。

    #[error("unspent output already exists: {outpoint:?}")]
    DuplicateOutput { outpoint: OutPoint },
}

/// 当前最佳链中的一个未花费交易输出。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoEntry {
    tx_out: TxOut,
    height: u32,
    is_coinbase: bool,
}

/// 为只需要查询未花费输出的模块提供最小读取接口。
pub trait UtxoView {
    fn get_unspent_output(&self, outpoint: &OutPoint) -> Option<&TxOut>;
}

impl UtxoEntry {
    /// 创建 UTXO 条目，并记录输出的创建高度和是否来自 coinbase。
    pub fn new(tx_out: TxOut, height: u32, is_coinbase: bool) -> Self {
        Self {
            tx_out,
            height,
            is_coinbase,
        }
    }

    /// 获取未花费交易输出。
    pub fn tx_out(&self) -> &TxOut {
        &self.tx_out
    }

    /// 获取该输出被创建时的区块高度。
    pub fn height(&self) -> u32 {
        self.height
    }

    /// 判断该输出是否来自 coinbase 交易。
    pub fn is_coinbase(&self) -> bool {
        self.is_coinbase
    }
}

/// 当前最佳链对应的内存 UTXO 集
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UtxoSet {
    coins: HashMap<OutPoint, UtxoEntry>,
}
impl UtxoSet {
    /// 创建空的内存 UTXO 集
    pub fn new() -> Self {
        Self::default()
    }

    /// 获取当前 UTXO 数量
    pub fn len(&self) -> usize {
        self.coins.len()
    }

    /// 判断当前 UTXO 集是否为空
    pub fn is_empty(&self) -> bool {
        self.coins.is_empty()
    }

    /// 获取指定未花费输出
    pub fn get(&self, outpoint: &OutPoint) -> Option<&UtxoEntry> {
        self.coins.get(outpoint)
    }

    /// 判断指定未花费输出是否存在
    pub fn contains(&self, outpoint: &OutPoint) -> bool {
        self.coins.contains_key(outpoint)
    }

    /// 插入新的 UTXO，拒绝覆盖已经存在的输出
    pub fn insert(&mut self, outpoint: OutPoint, entry: UtxoEntry) -> Result<(), UtxoError> {
        if self.contains(&outpoint) {
            return Err(UtxoError::DuplicateOutput { outpoint });
        }
        self.coins.insert(outpoint, entry);
        Ok(())
    }

    /// 移除指定 UTXO，不存在时返回 None
    pub fn remove(&mut self, outpoint: &OutPoint) -> Option<UtxoEntry> {
        self.coins.remove(outpoint)
    }

    /// 从 UTXO 集中移除一个输出，并返回被移除的 UtxoEntry
    /// 如果不存在，说明输入引用不存在或已经被花费。
    pub fn spend_output(&mut self, outpoint: &OutPoint) -> Result<UtxoEntry, UtxoError> {
        self.remove(outpoint).ok_or(UtxoError::MissingOutput { outpoint: *outpoint })
    }

    /// 把一笔交易的所有输出加入 UTXO 集。
    /// 1. coinbase 标记由 tx.is_coinbase() 决定
    /// 2. outpoint.hash 使用 tx.txid()
    /// 3. outpoint.n 使用输出下标
    /// 4. 采用先判重，再添加的方式，避免存在错误添加的情况下，回滚UTXO集合
    pub fn add_transaction_outputs(&mut self, tx: &Transaction, height: u32) -> Result<(), UtxoError> {
        let txid = tx.txid();
        let is_coinbase = tx.is_coinbase();

        // 判重
        if let Some(outpoint) = tx.vout.iter()
            .enumerate()
            .map(|(index, _)| OutPoint::new(txid, index as u32))
            .find(|outpoint| self.contains(outpoint)) {
            return Err(UtxoError::DuplicateOutput { outpoint });
        }

        // 依次添加
        tx.vout.iter().enumerate().try_for_each(|(index, txout)| {
            let outpoint = OutPoint::new(txid, index as u32);
            let entry = UtxoEntry::new(txout.clone(), height, is_coinbase);
            self.insert(outpoint, entry)
        })
    }
}

/// 为 mempool 提供只读 UtxoView
impl UtxoView for UtxoSet {
    fn get_unspent_output(&self, outpoint: &OutPoint) -> Option<&TxOut> {
        self.get(outpoint).map(UtxoEntry::tx_out)
    }
}
