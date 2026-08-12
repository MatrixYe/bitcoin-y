//! @Name: mempool
//!
//! @Date: 2026/7/13 17:14
//!
//! @Author: Matrix.Ye
//!
//! @Description: 交易内存池，负责管理全局状态之临时交易,
//!

use crate::cons::{MAX_BLOCK_SIGOPS, MAX_BLOCK_SIZE_GEN};
use crate::transaction::{InPoint, OutPoint, Transaction, TransactionError, TxOut};
use crate::uint256::Uint256;
use log::{debug, info, warn};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

/// 内存池错误。
///
/// 这里只描述 mempool 自身可以判断的问题；
/// 需要 UTXO、脚本、签名上下文的问题应放到 validation 阶段。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MempoolError {
    // 交易本身的错误
    #[error("transaction error: {0}")]
    Transaction(#[from] TransactionError),

    // 存在coinbase交易
    #[error("coinbase transaction cannot be accepted into mempool")]
    Coinbase,

    // 重复交易
    #[error("transaction already exists in mempool: {txid}")]
    Duplicate { txid: Uint256 },

    // 内存池交易双花 double spend
    #[error("transaction input already spent in mempool: {prevout:?}")]
    Conflict { prevout: OutPoint },

    // 找不到输入引用的前序输出
    #[error("missing prevout: {prevout:?}")]
    MissingPrevout { prevout: OutPoint },

    // 输入金额小于输出金额
    #[error("transaction input value {value_in} is less than output value {value_out}")]
    FeeUnderflow { value_in: u64, value_out: u64 },

    // 金额累加溢出
    #[error("transaction value overflow")]
    ValueOverflow,
}

/// UTXO 读取视图。
///
/// Mempool 不直接决定 UTXO 存在哪里；它只要求调用方能按 OutPoint 查到未花费输出。
/// 当前可以由内存 UTXO 集实现，后续也可以由本地数据库加缓存实现。
pub trait UtxoView {
    fn get_unspent_output(&self, outpoint: &OutPoint) -> Option<&TxOut>;
}

/// 内存中交易实体，原版只包含了Ctran
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemTxEntry {
    tx: Transaction,
    fee: u64,
    size: usize,
    sig_ops: usize,
}

impl MemTxEntry {
    pub fn from_tx(tx: Transaction, fee: u64) -> Self {
        // 获取交易大小
        let size = tx.get_size();
        let sig_ops: usize = tx.get_sig_op_count();

        Self { tx, fee, size, sig_ops }
    }

    pub fn tx(&self) -> &Transaction {
        &self.tx
    }

    pub fn fee(&self) -> u64 {
        self.fee
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn sig_ops(&self) -> usize {
        self.sig_ops
    }

    /// 计算手续费费率
    ///
    /// $fee_rate=fee*1000/size$
    pub fn fee_rate(&self) -> u64 {
        if self.size == 0 {
            return 0;
        }
        self.fee.saturating_mul(1000) / self.size as u64
    }
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mempool {
    //保存“输入已知且可接受”的未确认交易
    transactions: HashMap<Uint256, MemTxEntry>,
    //保存“暂时缺少前序输入”的交易
    orphan_transactions: HashMap<OutPoint, Uint256>,
    next_tx: HashMap<OutPoint, InPoint>,
    n_transactions_updated: u32,

}

impl Mempool {
    pub fn new() -> Self {
        Self {
            transactions: HashMap::new(),
            orphan_transactions: HashMap::new(),
            next_tx: HashMap::new(),
            n_transactions_updated: 0,
        }
    }
    fn update(&mut self) {
        info!("updating mempool");
        self.n_transactions_updated = self.n_transactions_updated.saturating_add(1);
    }

    /// 池内双花：查找当前交易是否和 mempool 中已有交易花费了同一个 OutPoint
    fn find_mempool_conflict(&self, tx: &Transaction) -> Option<OutPoint> {
        for vin in tx.vin.iter() {
            if self.next_tx.contains_key(&vin.prevout) {
                return Some(vin.prevout);
            }
        }
        None
    }

    /// # 验证交易并尝试加入内存池
    /// 1. 拒绝coinbase
    /// 2. 时间锁 todo
    /// 3. 拒绝非法Tx
    /// 4. 拒绝重复加入
    /// 5. 拒绝池内双花交易
    pub fn accept_to_mempool<U>(&mut self, tx: &Transaction, utxo: &U) -> Result<(), MempoolError>
    where
        U: UtxoView,
    {
        let txid = tx.txid();
        // 不可以是coinbase交易
        if tx.is_coinbase() {
            return Err(MempoolError::Coinbase);
        }
        // 检查 nLockTime 限制 todo

        // 交易本身的合法性检查(无上下文的)
        tx.check_transaction()?;

        // 交易不可以重复加入
        if self.already_have(&txid) {
            return Err(MempoolError::Duplicate { txid });
        }

        // menpool 内的双花直接拒绝，暂时不考虑BRF方案，tmd太复杂了
        if let Some(prevout) = self.find_mempool_conflict(tx) {
            return Err(MempoolError::Conflict { prevout });
        }

        // 构造TxEntry实体。手续费必须基于 UTXO 或 mempool 父交易计算，不能从交易自身直接得出。
        let fee = self.calculate_fee(tx, utxo)?;
        let entry = MemTxEntry::from_tx(tx.clone(), fee);

        // 加入到内存池中
        self.accept_to_mempool_uncheck(txid, entry);
        Ok(())
    }

    /// # 无验证加入内存池
    /// 1. 更新 未确认交易集合
    /// 2. 更新 Point In 和 Point Out的连接
    /// 3. 更新交易计数器
    fn accept_to_mempool_uncheck(&mut self, txid: Uint256, entry: MemTxEntry) {
        //1. 把交易放入 mapTransactions
        self.transactions.insert(txid, entry.clone());
        //2. 为每个输入在 mapNextTx 建立 outpoint -> inpoint 的索引
        for (n, vin) in entry.tx.vin.iter().enumerate() {
            self.next_tx.insert(vin.prevout, InPoint::new(txid, n as u32));
        }
        // 3.更新交易池变动计数器
        self.update();
    }

    /// 读取mempool中的交易实体
    pub fn get_entry(&self, txid: &Uint256) -> Option<&MemTxEntry> {
        self.transactions.get(txid)
    }

    /// 读取mempool 中的交易
    pub fn get_transactions(&self, txid: &Uint256) -> Option<&Transaction> {
        self.get_entry(txid).map(|entry| &entry.tx)
    }


    /// 删除交易，并删除 mapNextTx 中对应输入索引
    pub fn remove_from_mempool(&mut self, txid: &Uint256) -> Option<Uint256> {
        if let Some(entry) = self.transactions.remove(txid) {
            for txin in &entry.tx.vin {
                let outpoint = &txin.prevout;
                let result = self.next_tx.remove(outpoint);
                info!("disconnect next_tx,txid = {} n = {}, success: {}", outpoint.hash,outpoint.n,result.is_some());
            }
            info!("removed mempool txid={}", txid);
            return Some(txid.clone());
        }
        None
    }

    /// 当新区块连接到主链后，从 mempool 中移除已经入块的交易。
    pub fn remove_block_txs_from_mempool(&mut self, txids: &[Uint256]) {
        debug!("remove_block_txs_from_mempool");
        for txid in txids {
            self.remove_from_mempool(txid);
        }
    }

    /// 检测交易已经在内存池、孤儿内存池中存在
    pub fn already_have(&self, txid: &Uint256) -> bool {
        self.transactions.contains_key(txid)
    }


    /// 收集交易，组建新区块使用
    ///
    /// 当前实现按 fee rate 从高到低排序，并处理 mempool 内父子依赖：
    /// 如果交易花费的是 mempool 内另一笔交易的输出，那么父交易必须先被选入候选区块。
    pub fn collect_for_block(&self, block_height: u32, block_time: u32) -> (Vec<Transaction>, u64) {
        let mut txs: Vec<Transaction> = Vec::new();
        let mut total_fees = 0u64;
        // `block_size`和`block_sig_ops`的默认值不是严格的共识
        // 而是一个近似的预留空间，其中区块头定死了80字节，加上coinbase的大小，预估而已
        let mut block_size = 1000usize;
        let mut block_sig_ops = 100usize;
        // 结果容器
        let mut selected = HashSet::new();

        // 当前内存池内的候选交易集合
        let mut candidates: Vec<&MemTxEntry> = self.transactions.values().collect();

        // 对内存池内的交易集合进行排序
        // 这不是 Bitcoin v0.3.19 原版的完整排序策略，是我自定义的简化版矿工选择策略
        // 区块空间有限，所以优先选择单位字节手续费更高的交易更符合现代矿工经济直觉
        // 早期逻辑是priority = sum(input_value * input_age) / tx_size
        // 当前自定义逻辑是：
        // 1. fee_rate 高的优先。
        // 2. fee_rate 一样时，绝对手续费 fee 高的优先。
        // 3. fee 也一样时，体积小的优先。
        candidates.sort_by(|left, right| {
            right.fee_rate().cmp(&left.fee_rate())
                .then_with(|| right.fee.cmp(&left.fee))
                .then_with(|| left.size.cmp(&right.size))
        });

        let mut made_progress = true;
        while made_progress {
            made_progress = false;

            for entry in &candidates {
                let txid = entry.tx.txid();
                // 跳过 重复选择
                if selected.contains(&txid) {
                    warn!("repeated tx couldn't be collected");
                    continue;
                }
                // 跳过 coinbase交易
                if entry.tx.is_coinbase() {
                    warn!("coinbase tx couldn't be collected");
                    continue;
                }
                // 跳过 时间限制交易，根据tx.locktime 和blocktime/blockheight判断
                if !entry.tx.is_final_at(block_height, block_time) {
                    continue;
                }

                if !self.parents_selected(&entry.tx, &selected) {
                    continue;
                }

                // 区块体积限制
                if block_size + entry.size >= MAX_BLOCK_SIZE_GEN {
                    warn!("block size exceeded");
                    continue;
                }
                // 区块中签名操作码数量限制
                if block_sig_ops + entry.sig_ops >= MAX_BLOCK_SIGOPS {
                    warn!("block sigops exceeded");
                    continue;
                }
                block_size += entry.size;
                block_sig_ops += entry.sig_ops;
                total_fees = total_fees.saturating_add(entry.fee);
                selected.insert(txid);
                txs.push(entry.tx.clone());
                made_progress = true;
            }
        }

        (txs, total_fees)
    }

    /// 根据输入引用的前序输出计算手续费。
    ///
    /// fee = sum(prevout.value for each input) - sum(txout.value for each output)
    ///
    /// 输入金额来源有两类：
    /// 1. 如果前序交易还在 mempool 中，从 mempool 父交易的 vout 读取。
    /// 2. 否则从 UTXO 视图读取。
    fn calculate_fee<U>(&self, tx: &Transaction, utxo: &U) -> Result<u64, MempoolError>
    where
        U: UtxoView,
    {
        // 计算输出金额总和
        let value_out = tx.vout.iter().try_fold(0u64, |acc, txout| {
            acc.checked_add(txout.value).ok_or(MempoolError::ValueOverflow)
        })?;

        // 计算输入金额总和
        let value_in = tx.vin.iter().try_fold(0u64, |acc, txin| {
            let x = self.get_mempool_unspent_output(&txin.prevout)
                .or_else(|| utxo.get_unspent_output(&txin.prevout))
                .ok_or(MempoolError::MissingPrevout { prevout: txin.prevout })?;
            acc.checked_add(x.value).ok_or(MempoolError::ValueOverflow)
        })?;

        // 输入总和 - 输出总和 = 手续费
        value_in.checked_sub(value_out).ok_or(MempoolError::FeeUnderflow {
            value_in,
            value_out,
        })
    }

    fn get_mempool_unspent_output(&self, outpoint: &OutPoint) -> Option<&TxOut> {
        let entry = self.transactions.get(&outpoint.hash)?;
        entry.tx.vout.get(outpoint.n as usize)
    }

    fn parents_selected(&self, tx: &Transaction, selected: &HashSet<Uint256>) -> bool {
        tx.vin.iter().all(|txin| {
            !self.transactions.contains_key(&txin.prevout.hash)
                || selected.contains(&txin.prevout.hash)
        })
    }
}

