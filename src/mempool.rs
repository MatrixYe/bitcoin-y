//! @Name: mempool
//!
//! @Date: 2026/7/13 17:14
//!
//! @Author: Matrix.Ye
//!
//! @Description: 交易内存池，负责管理全局状态之临时交易,
//!

use crate::transaction::Transaction;
use crate::uint256::Uint256;
use std::collections::HashMap;

pub struct Mempool {
    pub transactions: HashMap<Uint256, Transaction>,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            transactions: HashMap::new(),
        }
    }

    fn contains_tx(&self, tx_hash: &Uint256) -> bool {
        self.transactions.contains_key(tx_hash)
    }

    /// 添加交易到内存池
    pub fn add_transaction(&mut self, tx: &Transaction) {
        let txid = tx.txid();
        // 去重复
        if self.contains_tx(&txid) {
            return;
        }
        // 排除coinbase
        if tx.is_coinbase() {
            return;
        }
        self.transactions.insert(txid.clone(), tx.clone());
        todo!("add transaction")
    }

    /// 从内存池中移除交易 by TxId
    pub fn remove_transaction(&mut self, txid: &Uint256) {
        self.transactions.remove(txid);
    }

    /// 收集交易，构造区块
    pub fn collect_for_block(&self) -> (Vec<Transaction>, u64) {
        let txs: Vec<Transaction> = vec![];
        let fee: u64 = 0;
        // todo
        for (txid, tx) in &self.transactions {
            if tx.is_coinbase() || !tx.is_final(){
                continue;
            }
        }
        (txs, fee)
    }
}