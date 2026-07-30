//! @Name: mempool
//!
//! @Date: 2026/7/13 17:14
//!
//! @Author: Matrix.Ye
//!
//! @Description: 交易内存池，负责管理全局状态之临时交易,
//!

use crate::cons::{MAX_BLOCK_SIGOPS, MAX_BLOCK_SIZE};
use crate::transaction::{InPoint, OutPoint, Transaction, TransactionError};
use crate::uint256::Uint256;
use log::{debug, info, warn};
use std::collections::HashMap;
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
    pub fn from_tx(tx: Transaction) -> Self {
        // 获取交易大小
        let size = tx.get_size();
        // 获取交易输出金额大小
        let value_out = tx.get_value_out();
        // 获取交易输入金额大小 todo
        let value_in: u64 = 1000;
        // 计算单笔交易手续费
        let fee = value_in - value_out;

        let sig_ops: usize = tx.get_sig_op_count();

        Self { tx, fee, size, sig_ops }
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
        todo!()
    }
    fn update(&mut self) {
        info!("updating mempool");
        self.n_transactions_updated = self.n_transactions_updated.saturating_add(1);
    }

    /// 判断是否存在mempool 内双花
    fn inculd_spent(&self, tx: &Transaction) -> Option<OutPoint> {
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
    pub fn accept_to_mempool(&mut self, tx: &Transaction) -> Result<(), MempoolError> {
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
        if let Some(prevout) = self.inculd_spent(tx) {
            return Err(MempoolError::Conflict { prevout });
        }

        // 构造TxEntry实体
        let entry = MemTxEntry::from_tx(tx.clone());

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
    pub fn collect_for_block(&self) -> (Vec<Transaction>, u64) {
        let mut txs: Vec<Transaction> = Vec::new();
        let mut total_fees = 0u64;
        let mut block_size = 0;
        let mut block_sig_ops = 0;

        for entry in self.transactions.values() {
            if entry.tx.is_coinbase() {
                warn!("coinbase tx couldn't be collected");
                continue;
            }

            if block_size + entry.size >= MAX_BLOCK_SIZE {
                warn!("block size exceeded");
                continue;
            }

            if block_sig_ops + entry.sig_ops >= MAX_BLOCK_SIGOPS {
                warn!("block sigops exceeded");
                continue;
            }
            block_size += entry.size;
            block_sig_ops += entry.sig_ops;
            total_fees = total_fees.saturating_add(entry.fee);
            txs.push(entry.tx.clone());
        }
        (txs, total_fees)
    }
}

