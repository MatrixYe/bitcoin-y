//! @Name: mempool
//!
//! @Date: 2026/7/13 17:14
//!
//! @Author: Matrix.Ye
//!
//! @Description: 负责交易池管理
//!

use crate::transaction::Transaction;
use crate::uint256::Uint256;
use std::collections::HashMap;

pub struct Mempool {
    pub txs: HashMap<Uint256, Transaction>,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            txs: HashMap::new(),
        }
    }

    pub fn add_transaction(&self, tx: &Transaction) {
        unimplemented!();
    }

    pub fn remove_transaction(&self, tx: &Transaction) {
        unimplemented!();
    }
}