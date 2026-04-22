use crate::hash::Hash256;
use crate::script::Script;

pub const COINBASE_N: u32 = u32::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct OutPoint {
    pub hash: Hash256,
    pub n: u32,
}

impl OutPoint {
    pub const fn null() -> Self {
        Self {
            hash: Hash256::zero(),
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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Transaction {
    pub version: i32,
    pub vin: Vec<TxIn>,
    pub vout: Vec<TxOut>,
    pub lock_time: u32,
}

pub fn is_coinbase(tx: &Transaction) -> bool {
    tx.vin.len() == 1 && tx.vin[0].prevout == OutPoint::null()
}
