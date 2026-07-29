//! @Name: block
//!
//! @Date: 2026/6/15 17:35
//!
//! @Author: Matrix.Ye
//!
//! @Description: 区块数据结构

use crate::bignum::BigNum;
use crate::codec::serialize_block;
use crate::codec::serialize_block_header;
use crate::cons::{MAX_BLOCK_SIGOPS, MAX_BLOCK_SIZE, POW_TARGT_LIMIT};
use crate::hash::sha256d;
use crate::merkle::compute_merkle_root;
use crate::pow::{check_proof_of_work, PowError};
use crate::transaction::{Transaction, TransactionError};
use crate::uint256::Uint256;
use crate::utils::get_adjusted_time;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BlockError {
    // 交易集第一个必须为coinbase Tx
    #[error("Coinbase tx must be first tx in block vtx ")]
    MissingCoinbase,

    #[error("Coinbase tx too many ")]
    TooManyCoinbase,

    // 空白的交易集合，最小为1
    #[error("Transactions within the block cannot be empty.")]
    EmptyTxData,

    // 区块大小爆炸
    #[error("The maximum block size is {maximum}, but the actual size is {actual}.")]
    BlockSizeOverflow {
        maximum: usize,
        actual: usize,
    },

    // 默克尔树根对不上
    #[error("block's merkle tree root not equal cal by txs")]
    UnmatchedMerkleRoot { expect: Uint256, actual: Uint256 },

    // 工作量相关错误
    #[error("pow error: {0}")]
    PowError(#[from] PowError),

    #[error("transaction error: {0}")]
    TxError(#[from] TransactionError),

    // 区块时间太晚了，大幅度超过未来时间
    #[error("CheckBlock() : block timestamp {block_time} is too far in the future {allow_future_time}"
    )]
    TimeTooFar { block_time: u32, allow_future_time: u32 },

    // 区块时间太早，超过了前序区块
    #[error("AcceptBlock() : block's timestamp is too early")]
    TimeTooEarly,

    #[error("CheckBlock() : too many sigops, max {maximum}, actual {actual}")]
    TooManySigOps {
        maximum: usize,
        actual: usize,
    },
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

    /// 计算传统 Bitcoin 区块头哈希。现代比特币的隔离见证方案把区块结构搞得乱七八糟的，这里不实现了。
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
    pub fn new() -> Block {
        Block {
            header: BlockHeader::new(),
            vtx: Vec::new(),
        }
    }
    pub fn set_version(&mut self, version: i32) {
        self.header.version = version;
    }
    pub fn set_prev_block(&mut self, prev_block: Uint256) { self.header.prev_block = prev_block; }
    pub fn set_merkle_root(&mut self, merkle_root: Uint256) { self.header.merkle_root = merkle_root; }
    pub fn set_time(&mut self, time: u32) {
        self.header.time = time;
    }
    pub fn set_bits(&mut self, bits: u32) {
        self.header.bits = bits;
    }
    pub fn set_nonce(&mut self, nonce: u32) {
        self.header.nonce = nonce;
    }


    pub fn get_block_time(&self) -> u32 {
        self.header.time
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
            return Err(BlockError::MissingCoinbase);
        }
        self.vtx[0].vout[0].value = value;
        Ok(value)
    }
}


impl Block {
    /// 获取区块哈希，即区块头哈希
    pub fn hash(&self) -> Uint256 {
        self.header.hash()
    }

    /// 计算区块头的默克尔树根
    /// 备注：计算默克尔树根和构建默克尔树是两码事
    pub fn get_merkle_root(&self) -> Uint256 {
        let txids: Vec<Uint256> = self.vtx.iter().map(|x| x.txid()).collect();
        compute_merkle_root(txids) // 引用merkle.rs的函数
    }

    /// 统计区块内所有交易脚本的签名检查操作数量。
    pub fn get_sig_op_count(&self) -> usize {
        self.vtx.iter().map(|tx| tx.get_sig_op_count()).sum()
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

    /// # 区块的基础合法性检查
    /// 参考：main.cpp bool CBlock::CheckBlock()
    /// > These are checks that are independent of context
    /// > that can be verified before saving an orphan block.
    ///
    ///  主要做“区块自身格式和基本内容是否正确”的检查
    /// 这些检查与上下文无关，可在保存孤儿区块之前进行验证。与上下文相关的检查在后续`AcceptBlock`、`ConnectBlock`、`SetBestChain`中完成
    pub fn check_block(&self) -> Result<(), BlockError> {
        // 1. 大小检查
        if self.vtx.is_empty() {
            return Err(BlockError::EmptyTxData);
        }

        let serialized_size = serialize_block(self).len();
        if serialized_size > MAX_BLOCK_SIZE {
            return Err(BlockError::BlockSizeOverflow {
                maximum: MAX_BLOCK_SIZE,
                actual: serialized_size,
            });
        }
        // 2. 工作量检查
        check_proof_of_work(self.hash(), self.header.bits, POW_TARGT_LIMIT)?;

        // 3.时间检查
        let block_time = self.get_block_time();
        let allow_future_time = get_adjusted_time() + 2 * 60 * 60;
        if block_time > allow_future_time {
            return Err(BlockError::TimeTooFar { block_time, allow_future_time });
        }
        // 3.交易检测
        // - 首交易必须为coinbase;
        // - 除了首交易，其余交易都不可以为coinbase;
        // - 交易本身需要检测合法
        for (index, tx) in self.vtx.iter().enumerate() {
            if index == 0 && !tx.is_coinbase() {
                return Err(BlockError::MissingCoinbase);
            }

            if index != 0 && tx.is_coinbase() {
                return Err(BlockError::TooManyCoinbase);
            }
            // 逐笔检查交易自身格式
            tx.check_transaction()?
        }
        // 4. 检测签名相关的操作码数量是否超过阈值
        let sig_op_count = self.get_sig_op_count();
        if sig_op_count > MAX_BLOCK_SIGOPS {
            return Err(BlockError::TooManySigOps {
                maximum: MAX_BLOCK_SIGOPS,
                actual: sig_op_count,
            });
        }

        // 5. 检测默克尔树是否匹配
        let actual_merkle_root = self.get_merkle_root();
        if self.header.merkle_root != actual_merkle_root {
            return Err(BlockError::UnmatchedMerkleRoot {
                expect: self.header.merkle_root,
                actual: actual_merkle_root,
            });
        }
        Ok(())
    }
}
