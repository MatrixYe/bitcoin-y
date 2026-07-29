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
/// 这里只描述 mempool 自身可以判断的问题；需要 UTXO、脚本、签名上下文的问题应放到 validation 阶段。
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


// /// 记录某个 outpoint 当前被 mempool 中哪笔交易的哪个输入占用。
// ///
// /// 对应原版 `mapNextTx` 的 Rust 化表达：用于快速发现内存池内双花冲突。
// #[derive(Debug, Clone, Copy, PartialEq, Eq)]
// pub struct MempoolInput {
//     pub txid: Uint256,
//     pub input_index: usize,
// }
//
// /// 内存池交易条目。
// ///
// /// 原版 `mapTransactions` 只保存 `CTransaction`；这里额外缓存 txid、大小、sigops、fee，
// /// 方便后续挖矿选交易时不重复计算。
// #[derive(Debug, Clone, PartialEq, Eq)]
// pub struct MempoolEntry {
//     pub txid: Uint256,
//     pub tx: Transaction,
//     pub fee: u64,
//     pub size: usize,
//     pub sig_ops: usize,
// }
//
// #[derive(Debug, Clone, Default)]
// pub struct Mempool {
//     /// 对应原版 `mapTransactions`：txid -> 交易条目。
//     transactions: HashMap<Uint256, MempoolEntry>,
//
//     /// 对应原版 `mapNextTx`：被花费的 outpoint -> 花费它的 mempool 输入。
//     ///
//     /// 这个索引用于阻止两笔未确认交易在本地 mempool 中花费同一个 outpoint。
//     next_tx: HashMap<OutPoint, MempoolInput>,
// }
//
// impl Mempool {
//     pub fn new() -> Self {
//         Self::default()
//     }
//
//     /// 返回当前 mempool 中的交易数量。
//     pub fn len(&self) -> usize {
//         self.transactions.len()
//     }
//
//     /// 判断 mempool 是否为空。
//     pub fn is_empty(&self) -> bool {
//         self.transactions.is_empty()
//     }
//
//     /// 判断某笔交易是否已经在 mempool 中。
//     pub fn contains_tx(&self, txid: &Uint256) -> bool {
//         self.transactions.contains_key(txid)
//     }
//
//     /// 读取 mempool 中的交易条目。
//     pub fn get_entry(&self, txid: &Uint256) -> Option<&MempoolEntry> {
//         self.transactions.get(txid)
//     }
//
//     /// 读取 mempool 中的交易。
//     pub fn get_transaction(&self, txid: &Uint256) -> Option<&Transaction> {
//         self.transactions.get(txid).map(|entry| &entry.tx)
//     }
//
//     /// 添加交易到内存池
//     ///
//     /// 当前版本只做 mempool 自身能判断的基础检查：
//     /// 1. 交易自身格式必须通过 `CheckTransaction`。
//     /// 2. coinbase 不能作为普通游离交易进入 mempool。
//     /// 3. txid 不能重复。
//     /// 4. 输入不能和 mempool 中已有交易冲突。
//     ///
//     /// 后续 validation 完成后，UTXO 存在性、脚本签名、手续费是否足够应在进入这里之前完成。
//     pub fn add_transaction(&mut self, tx: Transaction, fee: u64) -> Result<Uint256, MempoolError> {
//         tx.check_transaction()?;
//         let txid = tx.txid();
//
//         if self.contains_tx(&txid) {
//             return Err(MempoolError::Duplicate { txid });
//         }
//
//         if tx.is_coinbase() {
//             return Err(MempoolError::Coinbase);
//         }
//
//         for txin in &tx.vin {
//             if self.next_tx.contains_key(&txin.prevout) {
//                 return Err(MempoolError::Conflict {
//                     prevout: txin.prevout,
//                 });
//             }
//         }
//
//         let entry = MempoolEntry::new(txid, tx, fee);
//         self.index_inputs(&entry);
//         self.transactions.insert(txid, entry);
//         Ok(txid)
//     }
//
//     /// 从内存池中移除交易 by TxId
//     pub fn remove_transaction(&mut self, txid: &Uint256) -> Option<Transaction> {
//         let entry = self.transactions.remove(txid)?;
//         self.unindex_inputs(&entry);
//         Some(entry.tx)
//     }
//
//     /// 当新区块连接到主链后，从 mempool 中移除已经入块的交易。
//     pub fn remove_block_transactions(&mut self, txs: &[Transaction]) {
//         for tx in txs {
//             let txid = tx.txid();
//             self.remove_transaction(&txid);
//         }
//     }
//
//     /// 判断某个 outpoint 是否已经被 mempool 中的交易占用。
//     pub fn is_spent_in_mempool(&self, prevout: &OutPoint) -> bool {
//         self.next_tx.contains_key(prevout)
//     }
//
//     /// 收集交易，构造区块
//     ///
//     /// 当前先保持最小实现：按插入到 HashMap 后的遍历顺序尝试收集，后续再实现原版 priority/fee 选择。
//     /// 实现完整版本时需要：
//     /// 1. 跳过 coinbase 和非 final 交易。
//     /// 2. 检查区块大小不超过 `MAX_BLOCK_SIZE_GEN`。
//     /// 3. 检查区块 sigops 不超过 `MAX_BLOCK_SIGOPS`。
//     /// 4. 处理 mempool 内父子交易依赖，保证父交易先进入候选区块。
//     /// 5. 累计实际手续费，返回给 coinbase 计算区块价值。
//     pub fn collect_for_block(&self) -> (Vec<Transaction>, u64) {
//         let mut txs = Vec::new();
//         let mut total_fees = 0u64;
//         let mut block_size = 1000usize;
//         let mut block_sig_ops = 100usize;
//
//         for entry in self.transactions.values() {
//             if entry.tx.is_coinbase() {
//                 continue;
//             }
//             if block_size + entry.size >= MAX_BLOCK_SIZE_GEN {
//                 continue;
//             }
//             if block_sig_ops + entry.sig_ops >= MAX_BLOCK_SIGOPS {
//                 continue;
//             }
//
//             block_size += entry.size;
//             block_sig_ops += entry.sig_ops;
//             total_fees = total_fees.saturating_add(entry.fee);
//             txs.push(entry.tx.clone());
//         }
//
//         (txs, total_fees)
//     }
//
//     fn index_inputs(&mut self, entry: &MempoolEntry) {
//         for (input_index, txin) in entry.tx.vin.iter().enumerate() {
//             self.next_tx.insert(txin.prevout, MempoolInput {
//                 txid: entry.txid,
//                 input_index,
//             });
//         }
//     }
//
//     fn unindex_inputs(&mut self, entry: &MempoolEntry) {
//         for txin in &entry.tx.vin {
//             self.next_tx.remove(&txin.prevout);
//         }
//     }
// }
//
// impl MempoolEntry {
//     pub fn new(txid: Uint256, tx: Transaction, fee: u64) -> Self {
//         Self {
//             txid,
//             size: serialize_transaction(&tx).len(),
//             sig_ops: tx.get_sig_op_count(),
//             tx,
//             fee,
//         }
//     }
// }
