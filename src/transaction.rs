//! @Name: transaction
//!
//! @Date: 2026/4/23 09:55
//!
//! @Author: Matrix.Ye
//!
//! @Description: 交易

use crate::codec::deserialize_transaction;
use crate::codec::serialize_transaction;
use crate::cons::{MAX_BLOCK_SIZE, MAX_MONEY};
use crate::errors::CError;
use crate::hash::sha256d;
use crate::script::{count_sig_ops, Script};
use crate::uint256::Uint256;
use thiserror::Error;

// 原版语义中，coinbase的交易输入的前驱，n =-1,因为是无符号整数，所有实际为u32::MAX
// coinbase 输入使用的特殊输出索引 0xffff_ffff。反正不是0，参考源忘了，记得查过一次。
const COINBASE_N: u32 = u32::MAX;


#[derive(Debug, Clone, Eq, PartialEq, Error)]
pub enum TransactionError {
    #[error("tx.vin or tx.vout is empty")]
    EmptyVinOrVout,

    #[error("The transaction size is too large.")]
    TxSizeTooLarge,

    #[error("The transaction value is too large,> MAX_NONEY")]
    TxValueOverflow,

    #[error("The coinbase tx script size except in [2,100],but {actual_size}")]
    CoinbaseSciptSizeLimit { actual_size: usize },

    #[error("prevout of transaction is null")]
    TxPrevoutIsNull,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct OutPoint {
    pub hash: Uint256,
    pub n: u32,
}

impl OutPoint {
    pub fn new(hash: Uint256, n: u32) -> Self {
        OutPoint { hash, n }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct InPoint {
    pub hash: Uint256,
    pub n: u32,
}
impl InPoint {
    pub fn new(hash: Uint256, n: u32) -> Self {
        InPoint { hash, n }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TxIn {
    pub prevout: OutPoint,
    pub script_sig: Script,
    pub sequence: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: Script,
}

/// [参考资料：交易原始数据](https://bitcoindevelopers.org/docs/reference/transactions-ref/#raw-transaction-format)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Transaction {
    pub version: i32,
    pub vin: Vec<TxIn>,
    pub vout: Vec<TxOut>,
    pub lock_time: u32,
}

impl Transaction {
    /// 计算传统 Bitcoin txid。
    pub fn txid(&self) -> Uint256 {
        self.get_hash()
    }

    /// 获取交易哈希
    pub fn get_hash(&self) -> Uint256 {
        sha256d(&self.serialize()).into()
    }

    /// 序列化，协议参考 [bitcoin dev:reference:transactions](https://bitcoindevelopers.org/docs/reference/transactions-ref/)
    /// tx ==> bytes
    pub fn serialize(&self) -> Vec<u8> {
        serialize_transaction(self)
    }

    /// 反序列化
    /// bytes ==> tx
    pub fn deserialize(data: &[u8]) -> Result<Transaction, CError> {
        deserialize_transaction(data)
    }

    /// 判断是否是 coinbase 交易。
    pub fn is_coinbase(&self) -> bool {
        self.vin.len() == 1 && self.vin[0].prevout == OutPoint::NULL
    }

    pub fn is_final(&self) -> bool {
        todo!();
    }

    /// 构造一个初始状态的coinbase交易
    /// ## 初始化状态
    /// - `vin.len` =1
    /// - `vin[0].prevout = null`
    /// - value =0
    /// - script_sig = []
    /// - script_pubkey = []
    pub fn new_coinbase() -> Transaction {
        let mut coinbase = Transaction::default();

        coinbase.vin = vec![TxIn {
            prevout: OutPoint::set_null(),
            script_sig: Script::default(),
            sequence: u32::MAX,
        }];

        coinbase.vout = vec![TxOut {
            value: 0,
            script_pubkey: Script::default(),
        }];

        coinbase
    }

    /// 交易检测(无关上下文)
    pub fn check_transaction(&self) -> Result<(), TransactionError> {
        // 输入和输出不能为空
        if self.vin.is_empty() || self.vout.is_empty() {
            return Err(TransactionError::EmptyVinOrVout);
        }
        // 2. 交易大小不能超过`MAX_BLOCK_SIZE`：
        if self.get_size() > MAX_BLOCK_SIZE {
            return Err(TransactionError::TxSizeTooLarge);
        }

        //每个输出金额不能为负，不能超过 MAX_MONEY：
        let mut total_value = 0u64;
        for out in self.vout.iter() {
            if out.value > MAX_MONEY {
                return Err(TransactionError::TxValueOverflow);
            }
            // fix: check_transaction 的金额累加溢出问题，用 checked_add 避免 u64 溢出后绕回
            // 原版金额采用的是i64,没有必要，这里没有按中本聪的写法来
            total_value = total_value
                .checked_add(out.value)
                .ok_or(TransactionError::TxValueOverflow)?;
            if total_value > MAX_MONEY {
                return Err(TransactionError::TxValueOverflow);
            }
        }

        // 如果是coinbase 交易，需要检查输入脚本的长度在2～100 之间
        if self.is_coinbase() {
            let actual_size = self.vin[0].script_sig.len();
            if actual_size < 2 || actual_size > 100 {
                return Err(TransactionError::CoinbaseSciptSizeLimit { actual_size });
            }
        } else {
            // 如果是普通交易，那么所有交易输入的前序交易都不可为空
            for vin in self.vin.iter() {
                if vin.prevout.is_null() {
                    return Err(TransactionError::TxPrevoutIsNull);
                }
            }
        }
        Ok(())
    }

    /// 统计交易输入脚本和输出脚本中的签名检查操作数量。
    pub fn get_sig_op_count(&self) -> usize {
        let input_sig_ops = self.vin.iter()
            .map(|txin| count_sig_ops(&txin.script_sig))
            .sum::<usize>();
        let output_sig_ops = self.vout.iter()
            .map(|txout| count_sig_ops(&txout.script_pubkey))
            .sum::<usize>();
        input_sig_ops + output_sig_ops
    }

    // 获取交易输出集合的 金额累计
    pub fn get_value_out(&self) -> u64 {
        self.vout.iter().map(|v| v.value).sum::<u64>()
    }

    pub fn get_size(&self) -> usize {
        self.serialize().len()
    }

    pub fn size_limit(&self, min_size: usize, max_size: usize) -> bool {
        let size = self.get_size();
        size >= min_size && size <= max_size
    }
}

impl OutPoint {
    pub const NULL: Self = Self::set_null();
    pub fn null() -> Self {
        Self::set_null()
    }
    pub const fn set_null() -> Self {
        Self {
            hash: Uint256::ZERO, // coinbase pre hash
            n: COINBASE_N,
        }
    }
    // 判断是否为NULL
    pub fn is_null(&self) -> bool {
        self.hash == Uint256::ZERO && self.n == COINBASE_N
    }
}
