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

/// ## 内存池错误
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

/// # 核心结构：交易内存池
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mempool {
    //保存“输入已知且可接受”的未确认交易
    tx_entries: HashMap<Uint256, MemTxEntry>,
    //保存“暂时缺少前序输入”的交易
    orphan_transactions: HashMap<OutPoint, Uint256>,
    next_tx: HashMap<OutPoint, InPoint>,
    n_transactions_updated: u32,
}

/// ## 内存中交易实体
/// 和原版的实现的逻辑不一样，原版中通过多个全局变量来实现，这里进行了统一并增加了多个其他属性方便后续计算。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemTxEntry {
    txid: Uint256, // 在不考虑BRF的前提下，加入到内存池中的Tx是不变的，因此为了避免重复的txid计算，这里多加入了一个字段
    tx: Transaction,
    fee: u64, // 手续费
    size: usize, // 交易大小
    sig_ops: usize, // 交易包含的累积签名数量
}

/// ## UTXO 读取视图
///
/// Mempool 不直接决定 UTXO 存在哪里；它只要求调用方能按 OutPoint 查到未花费输出。
/// 当前可以由内存 UTXO 集实现，后续也可以由本地数据库加缓存实现。
pub trait UtxoView {
    fn get_unspent_output(&self, outpoint: &OutPoint) -> Option<&TxOut>;
}

impl MemTxEntry {
    pub fn from_tx(txid: Uint256, tx: Transaction, fee: u64) -> Self {
        // 获取交易大小
        let size = tx.get_size();
        let sig_ops: usize = tx.get_sig_op_count();

        Self { txid, tx, fee, size, sig_ops }
    }

    pub fn txid(&self) -> Uint256 {
        self.txid
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

impl Mempool {
    pub fn new() -> Self {
        Self {
            tx_entries: HashMap::new(),
            orphan_transactions: HashMap::new(),
            next_tx: HashMap::new(),
            n_transactions_updated: 0,
        }
    }

    /// # 验证交易并加入内存池
    /// 1. 拒绝coinbase
    /// 2. 时间锁
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
        // 检查 nLockTime 限制 todo 等待block height

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

        // 构造TxEntry实体。手续费必须基于 UTXO 或 mempool 的父交易计算，不能从交易自身直接得出。
        let fee = self.calculate_fee(tx, utxo)?;
        let entry = MemTxEntry::from_tx(txid, tx.clone(), fee);

        // 加入到内存池中
        self.accept_to_mempool_uncheck(txid, entry);
        Ok(())
    }
    
    /// 读取mempool 中的交易
    pub fn get_transactions(&self, txid: &Uint256) -> Option<&Transaction> {
        self.get_entry(txid).map(|entry| &entry.tx)
    }

    /// 删除交易条目，并删除 mapNextTx 中对应输入索引
    pub fn remove_from_mempool(&mut self, txid: &Uint256) -> Option<Uint256> {
        if let Some(entry) = self.remove_entry(txid) {
            for txin in &entry.tx.vin {
                let outpoint = &txin.prevout;
                let result = self.remove_next(outpoint);
                info!("disconnect next_tx,txid = {} n = {}, success: {}", outpoint.hash,outpoint.n,result.is_some());
            }
            info!("removed mempool txid={}", txid);
            return Some(txid.clone());
        }
        None
    }

    /// 当新区块连接到主链后，从 mempool 中移除已经入块的交易。
    pub fn remove_block_txs_from_mempool(&mut self, txids: &[Uint256]) {
        info!("new block,remove txs from mempool");
        for txid in txids {
            self.remove_from_mempool(txid);
        }
    }

    /// 收集交易，组建新区块使用
    ///
    /// 当前实现按 fee rate 从高到低排序，并处理 mempool 内父子依赖：
    /// 如果交易花费的是 mempool 内另一笔交易的输出，那么父交易必须先被选入候选区块。
    pub fn collect_for_block(&self, block_height: u32, block_time: u32) -> (Vec<Transaction>, u64) {
        // 目标交易集合
        let mut txs: Vec<Transaction> = Vec::new();
        let mut selected = HashSet::new();
        // 累计手续费
        let mut total_fees = 0u64;
        // `block_size`和`block_sig_ops`的默认值不是严格的共识
        // 而是一个近似的预留空间，其中区块头定死了80字节，加上coinbase的大小，预估而已
        let mut block_size = 1000usize;
        let mut block_sig_ops = 100usize;

        // 当前内存池内的交易集合
        let mut candidates: Vec<&MemTxEntry> = self.tx_entries.values().collect();

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

        let mut selected_any = true; //上一轮扫描是否成功选入了至少一笔交易。

        while selected_any {
            selected_any = false; // 当没有任何新交易被纳入待选集，扫描循环被终止，返回待选集和累积手续费

            for entry in &candidates {
                let txid = entry.txid();
                // 跳过 重复选择
                if selected.contains(&txid) {
                    debug!("repeated transaction couldn't be collected");
                    continue;
                }
                // 跳过 coinbase交易
                if entry.tx.is_coinbase() {
                    warn!("coinbase transaction couldn't be collected");
                    continue;
                }
                // 跳过 时间限制交易，根据tx.locktime 和blocktime/blockheight判断
                if !entry.tx.is_final_at(block_height, block_time) {
                    debug!("skip non-final transaction");
                    continue;
                }

                // 跳过 父交易不明确的待选交易
                if !self.parents_selected(&entry.tx, &selected) {
                    debug!("skip transaction waiting for mempool parents");
                    continue;
                }

                // 区块体积限制
                if block_size + entry.size >= MAX_BLOCK_SIZE_GEN {
                    debug!("skip transaction because block size exceeded");
                    continue;
                }
                // 区块中签名操作码数量限制
                if block_sig_ops + entry.sig_ops >= MAX_BLOCK_SIGOPS {
                    debug!("skip transaction because block sigops exceeded");
                    continue;
                }

                block_size += entry.size; // 累加到区块大小
                block_sig_ops += entry.sig_ops; // 累加到区块签名操作数
                total_fees = total_fees.saturating_add(entry.fee); // 累加手续费
                selected.insert(txid); // 将txid 添加到已选择交易索引中
                txs.push(entry.tx.clone()); // 将实体Tx添加到待打包交易集合中
                selected_any = true; // 更新本次循环中，找到新交易
            }
        }

        (txs, total_fees)
    }
    // 更新计数器
    fn update(&mut self) {
        debug!("updating mempool");
        self.n_transactions_updated = self.n_transactions_updated.saturating_add(1);
    }
    /// # 无验证加入内存池
    /// 1. 更新 未确认交易集合
    /// 2. 更新 Point In 和 Point Out的连接
    /// 3. 更新交易计数器
    fn accept_to_mempool_uncheck(&mut self, txid: Uint256, entry: MemTxEntry) {
        //1. 把交易放入 mapTransactions
        self.tx_entries.insert(txid, entry.clone());
        //2. 为每个输入在 mapNextTx 建立 outpoint -> inpoint 的索引
        for (n, vin) in entry.tx.vin.iter().enumerate() {
            self.next_tx.insert(vin.prevout, InPoint::new(txid, n as u32));
        }
        // 3.更新交易池变动计数器
        self.update();
    }

    // 读取mempool中的交易实体
    fn get_entry(&self, txid: &Uint256) -> Option<&MemTxEntry> {
        self.tx_entries.get(txid)
    }

    // 移除内存池指定条目
    fn remove_entry(&mut self, txid: &Uint256) -> Option<MemTxEntry> {
        self.tx_entries.remove(txid)
    }

    // 移除内存池内
    fn remove_next(&mut self, outpoint: &OutPoint) -> Option<InPoint> {
        self.next_tx.remove(outpoint)
    }

    // 池内双花：查找当前交易是否和 mempool 中已有交易花费了同一个 OutPoint
    fn find_mempool_conflict(&self, tx: &Transaction) -> Option<OutPoint> {
        for vin in tx.vin.iter() {
            if self.next_tx.contains_key(&vin.prevout) {
                return Some(vin.prevout);
            }
        }
        None
    }

    /// 检测交易已经在内存池、孤儿内存池中存在
    fn already_have(&self, txid: &Uint256) -> bool {
        self.tx_entries.contains_key(txid)
    }

    /// ## 计算手续费
    ///
    /// Tx对象并不会直接包含手续费，也无法直接计算。计算手续费的前提是找到前序交易。但Tx的vin只提供了前序交易的索引，并不包含值，所以需要先找到具体的前序交易的值后再计算手续费。
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
        let entry = self.tx_entries.get(&outpoint.hash)?;
        entry.tx.vout.get(outpoint.n as usize)
    }

    // 判断当前交易所有输入中，引用的父交易必须是明确的，它要么来自于已确认的区块，要么来自于已选择的未确认交易。
    // 对于每个输入引用的父亲交易：
    // 1. 要么在内存池中没找着：它大概率在UTXO集合中。
    // 2. 如果在内存池中有，那么它必须先一步加入到候选集中
    fn parents_selected(&self, tx: &Transaction, selected: &HashSet<Uint256>) -> bool {
        tx.vin.iter().all(|txin| {
            !self.tx_entries.contains_key(&txin.prevout.hash) || selected.contains(&txin.prevout.hash)
        })
    }
}

