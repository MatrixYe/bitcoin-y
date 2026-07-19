//! @Name: block
//!
//! @Date: 2026/6/15 17:35
//!
//! @Author: Matrix.Ye
//!
//! @Description: 区块数据结构

use crate::bignum::BigNum;
use crate::codec::serialize_block_header;
use crate::hash::sha256d;
use crate::merkle::compute_merkle_root;
use crate::transaction::Transaction;
use crate::uint256::Uint256;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BlockError {
    #[error("InvalidTransaction")]
    InvalidTransaction,

    #[error("InvalidVersion")]
    InvalidVersion,

    #[error("InvalidCoinbase")]
    InvalidCoinbase,

    #[error("InvalidTimestamp")]
    InvalidTimestamp,

    #[error("InvalidDifficulty")]
    InvalidDifficulty,

    #[error("InvalidNonce")]
    InvalidNonce,

    #[error("EmptyTxData")]
    EmptyTxData,
}


/// - version       4 字节
/// - prev_block   32 字节
/// - merkle_root  32 字节
/// - time          4 字节
/// - bits          4 字节
/// - nonce         4 字节

///```cpp
/// class CBlock
/// {
/// public:
/// // header
/// int nVersion;
/// uint256 hashPrevBlock;
/// uint256 hashMerkleRoot;
/// unsigned int nTime;
/// unsigned int nBits;
/// unsigned int nNonce;
///
/// // network and disk
/// vector<CTransaction> vtx;
///
/// // memory only
/// mutable vector<uint256> vMerkleTree;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BlockHeader {
    pub version: i32,
    pub prev_block: Uint256, // 禁止使用Option<Uint256>,因为必须保证区块头字节固定为80
    pub merkle_root: Uint256,
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Block {
    pub header: BlockHeader,
    pub vtx: Vec<Transaction>,
}

impl Block {
    pub fn new() -> Block {
        Block {
            header: BlockHeader::new(),
            vtx: Vec::new(),
        }
    }

    pub fn set_version(&mut self, version: i32) {
        self.header.version = version;
    }
    pub fn set_prev_block(&mut self, prev_block: Uint256) {
        self.header.prev_block = prev_block;
    }
    pub fn set_merkle_root(&mut self, merkle_root: Uint256) {
        self.header.merkle_root = merkle_root;
    }
    pub fn set_time(&mut self, time: u32) {
        self.header.time = time;
    }
    pub fn set_bits(&mut self, bits: u32) {
        self.header.bits = bits;
    }
    pub fn set_nonce(&mut self, nonce: u32) {
        self.header.nonce = nonce;
    }
    // 添加一笔交易
    pub fn push_tx(&mut self, tx: Transaction) {
        self.vtx.push(tx);
    }
    // 添加多笔交易
    pub fn push_txs(&mut self, txs: Vec<Transaction>) {
        self.vtx.extend_from_slice(&txs);
    }
    // 更新区块的coinbase 金额
    pub fn update_coinbase_value(&mut self, value: u64) -> Result<u64, BlockError> {
        if self.vtx.is_empty() {
            return Err(BlockError::EmptyTxData);
        }
        if !self.vtx[0].is_coinbase() {
            return Err(BlockError::InvalidCoinbase);
        }
        self.vtx[0].vout[0].value = value;
        Ok(value)
    }
}

impl BlockHeader {
    pub fn new() -> Self {
        BlockHeader {
            version: 1,
            prev_block: Uint256::ZERO,
            merkle_root: Uint256::ZERO,
            time: 0,
            bits: 0,
            nonce: 0,
        }
    }

    /// 计算传统 Bitcoin 区块头哈希。
    pub fn hash(&self) -> Uint256 {
        let head_ser = self.serialize();
        sha256d(&head_ser).into()
    }

    /// 区块头序列化
    pub fn serialize(&self) -> Vec<u8> {
        serialize_block_header(self).to_vec()
    }
}

impl Block {
    /// 获取区块哈希，即区块头哈希
    pub fn hash(&self) -> Uint256 {
        self.header.hash()
    }

    /// 计算区块头的默克尔树根
    pub fn build_merkle_root(&self) -> Uint256 {
        let txids: Vec<Uint256> = self.vtx.iter().map(|x| x.txid()).collect();
        compute_merkle_root(txids)
    }

    /// 计算此区块的工作量 `(CBigNum(1)<<256) / (bnTarget+1)`
    /// ```cpp
    ///     CBigNum GetBlockWork() const
    ///     {
    ///         CBigNum bnTarget;
    ///         bnTarget.SetCompact(nBits);
    ///         if (bnTarget <= 0)
    ///             return 0;
    ///         return (CBigNum(1)<<256) / (bnTarget+1);
    ///     }
    /// ```
    pub fn get_work(&self) -> BigNum {
        let target = BigNum::set_compact(self.header.bits);
        match target <= BigNum::zero() {
            true => BigNum::zero(),
            false => (BigNum::from_u32(1) << 256) / (target + BigNum::from_u32(1)),
        }
    }

    /// 检查区块工作量是否标准
    /// ```cpp
    ///     uint256 hash = pblock->GetHash();
    ///     uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();
    ///
    ///     if (hash > hashTarget)
    ///         return false;
    ///```
    pub fn check_work(&self) -> bool {
        let hash = self.hash();
        // let target = BigNum::set_compact(self.header.bits);
        let (target, negative, overflow) = Uint256::set_compact(self.header.bits);
        match negative || overflow || target.is_zero() {
            true => false,
            false => hash <= target,
        }
    }
}
