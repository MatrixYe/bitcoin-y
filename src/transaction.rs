use crate::codec::deserialize_transaction;
use crate::codec::serialize_transaction;
use crate::errors::CError;
use crate::hash::sha256d;
use crate::hash::Hash256;
use crate::script::Script;

/// coinbase 输入使用的特殊输出索引 `0xffff_ffff`。参考源忘了，反正查过一次。
const COINBASE_N: u32 = u32::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct OutPoint {
    pub hash: Hash256,
    pub n: u32,
}

impl OutPoint {
    pub const fn null() -> Self {
        Self {
            hash: Hash256::zero(), // coinbase pre hash
            n: COINBASE_N,
        }
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
    pub fn txid(&self) -> Hash256 {
        self.get_hash()
    }

    /// 获取交易哈希
    pub fn get_hash(&self) -> Hash256 {
        sha256d(&self.serialize())
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
        self.vin.len() == 1 && self.vin[0].prevout == OutPoint::null()
    }
}
