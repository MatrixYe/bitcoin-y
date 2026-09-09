//! @Name: utxo
//!
//! @Date: 2026/8/18 18:53
//!
//! @Author: Matrix.Ye
//!
//! @Description: 维护当前最佳链对应的未花费输出集合。

use crate::cons::COINBASE_MATURITY;
use crate::transaction::{OutPoint, Transaction, TxOut};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UtxoError {
    #[error("missing unspent output: {outpoint:?}")]
    MissingOutput { outpoint: OutPoint }, //输入引用的 OutPoint 不在 UTXO 集中

    #[error("coinbase output is not mature: {outpoint:?}, depth={depth},min_depth={min_depth}")]
    CoinbaseNotMature { outpoint: OutPoint, depth: u32, min_depth: u32 }, //花费 coinbase 但确认数不足

    #[error("invalid spend height: {outpoint:?}, created at {created_height}, spent at {spend_height}"
    )]
    InvalidSpendHeight {
        outpoint: OutPoint,
        created_height: u32,
        spend_height: u32,
    },

    #[error("duplicate transaction input: {outpoint:?}")]
    DuplicateInput { outpoint: OutPoint }, // 重复的输入

    #[error("UTXO value overflow")]
    ValueOverflow, //输入或输出金额累计溢出。

    #[error("transaction input value {value_in} is less than output value {value_out}")]
    ValueUnderflow { value_in: u64, value_out: u64 }, //输入金额小于输出金额。

    #[error("unspent output already exists: {outpoint:?}")]
    DuplicateOutput { outpoint: OutPoint }, // 异常输出，某个交易的输出与当前utxo集合中某个实体重复
}

/// 当前最佳链中的一个未花费交易输出。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoEntry {
    tx_out: TxOut,
    height: u32,
    is_coinbase: bool,
}

/// 连接交易时被花费的旧 UTXO，用于后续断开交易或区块时恢复状态。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConnectTxUndo {
    spent_outputs: Vec<(OutPoint, UtxoEntry)>,
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

impl ConnectTxUndo {
    /// 创建交易回滚记录。
    pub fn new(spent_outputs: Vec<(OutPoint, UtxoEntry)>) -> Self {
        Self { spent_outputs }
    }

    /// 获取本次交易连接时被花费的全部旧 UTXO。
    pub fn spent_outputs(&self) -> &[(OutPoint, UtxoEntry)] {
        &self.spent_outputs
    }

    /// 消费回滚记录并返回被花费的旧 UTXO。
    pub fn into_spent_outputs(self) -> Vec<(OutPoint, UtxoEntry)> {
        self.spent_outputs
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

    /// ## 连接一笔交易
    /// 花费输入引用的 UTXO，并创建该交易的全部输出。即花费旧硬币，产生新硬币。
    ///
    /// ### 流程
    /// 1. `Transaction::check_transaction` 等与 UTXO 无关的基础检查在之前就应该完成
    /// 2. 创建预备花费货币集合和预备生产货币集合
    /// 3. 检查新货币重复(创建重复货币)，-> 检查输入货币是否存在 -> 检查初始货币成熟度 -> 检查金额
    /// 4. 检查通过，统一进行移除和插入，更新全局状态
    /// 5. 返回`ConnectTxUndo`
    pub fn connect_transaction(&mut self, tx: &Transaction, height: u32) -> Result<ConnectTxUndo, UtxoError> {
        let txid = tx.txid();
        let is_coinbase = tx.is_coinbase();

        // 将交易输出转化为 outpoint->entry 的合集
        let new_outputs = tx.vout.iter()
            .enumerate()
            .map(|(index, tx_out)| {
                let outpoint = OutPoint::new(txid, index as u32);
                let entry = UtxoEntry::new(tx_out.clone(), height, is_coinbase);
                (outpoint, entry)
            })
            .collect::<Vec<_>>();

        // 判断当前交易输出是否在当前UTXO集合中重复，货币不仅不能双花，也不能重复制造
        if let Some((outpoint, _)) = new_outputs.iter().find(|(outpoint, _)| self.contains(outpoint)) {
            return Err(UtxoError::DuplicateOutput { outpoint: *outpoint });
        }

        // coinbase 不花费旧输出，只需要把新生成的输出加入当前 UTXO 集
        if is_coinbase {
            new_outputs.into_iter().for_each(|(outpoint, entry)| {
                self.coins.insert(outpoint, entry);
            });
            return Ok(ConnectTxUndo::default());
        }

        // 预备移除(花费)的utxo集合
        let mut prep_remove_utxos = Vec::with_capacity(tx.vin.len());
        // 预备插入的新的utxo集合
        let mut seen_inputs = HashSet::new();

        // 累计金额输入和累计金额输出
        let mut value_in = 0u64;
        // let mut value_out = 0u64;

        // 批量检查交易输入
        for txin in &tx.vin {
            let outpoint = txin.prevout;
            // 去重复的输入Utxo
            if !seen_inputs.insert(outpoint) {
                return Err(UtxoError::DuplicateInput { outpoint });
            }
            // 在当前utxo状态集合中查询，是否输入utxo存在
            let entry = self.get(&outpoint).ok_or(UtxoError::MissingOutput { outpoint })?;

            // 计算交易的深度
            let depth = height.checked_sub(entry.height)
                .ok_or(UtxoError::InvalidSpendHeight {
                    outpoint,
                    created_height: entry.height,
                    spend_height: height,
                })?;

            // 如果是coinbase交易，需要检查深度是否符合标准
            if entry.is_coinbase && depth < COINBASE_MATURITY {
                return Err(UtxoError::CoinbaseNotMature { outpoint, depth, min_depth: COINBASE_MATURITY });
            }

            // 累加，交易输入总金额
            value_in = value_in.checked_add(entry.tx_out.value).ok_or(UtxoError::ValueOverflow)?;
            // 插入预备花费集
            prep_remove_utxos.push((outpoint, entry.clone()));
        }

        // 累加 交易输出总金额
        let value_out = tx.vout.iter()
            .try_fold(0u64, |acc, txout| {
                acc.checked_add(txout.value).ok_or(UtxoError::ValueOverflow)
            })?;

        // 判断输出总金额是否大于输入总金额，如果是，即异常
        if value_out > value_in {
            return Err(UtxoError::ValueUnderflow { value_in, value_out });
        }

        // 前置检查全部通过后再提交修改，保证错误路径不会留下部分更新。
        prep_remove_utxos.iter().for_each(|(outpoint, _)| {
            self.coins.remove(outpoint);
        });
        new_outputs.into_iter().for_each(|(outpoint, entry)| {
            self.coins.insert(outpoint, entry);
        });

        // 最后返回
        Ok(ConnectTxUndo::new(prep_remove_utxos))
    }

    pub fn connect_block() {
        todo!()
    }
}

/// 为 mempool 提供只读 UtxoView
impl UtxoView for UtxoSet {
    fn get_unspent_output(&self, outpoint: &OutPoint) -> Option<&TxOut> {
        self.get(outpoint).map(UtxoEntry::tx_out)
    }
}
