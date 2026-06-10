use crate::bignum::BigNum;
use crate::codec::serialize_block_header;
use crate::hash::sha256d;
use crate::merkle::compute_merkle_root;
use crate::transaction::Transaction;
use crate::uint256::Uint256;


/// - version       4 字节
/// - prev_block   32 字节
/// - merkle_root  32 字节
/// - time          4 字节
/// - bits          4 字节
/// - nonce         4 字节

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
    pub txdata: Vec<Transaction>,
}

impl BlockHeader {
    /// 计算传统 Bitcoin 区块头哈希。
    pub fn block_hash(&self) -> Uint256 {
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
    pub fn get_hash(&self) -> Uint256 {
        self.header.block_hash()
    }

    /// 计算区块头的默克尔树根
    pub fn compute_merkle_root(&self) -> Uint256 {
        let txids: Vec<Uint256> = self.txdata.iter().map(|x| x.txid()).collect();
        compute_merkle_root(txids)
    }
}

/// main.h
///```cpp
///class CBlockIndex
/// {
/// public:
///     const uint256* phashBlock;
///     CBlockIndex* pprev;
///     CBlockIndex* pnext;
///     unsigned int nFile;
///     unsigned int nBlockPos;
///     int nHeight;
///     CBigNum bnChainWork;
///
///     // block header
///     int nVersion;
///     uint256 hashMerkleRoot;
///     unsigned int nTime;
///     unsigned int nBits;
///     unsigned int nNonce;
/// }
/// ```
pub struct BlockIndex {
    pub hash: Uint256,
    pub previous: Option<Uint256>,
    pub height: u32,
    pub time: u32,
    pub bits: u32,
    pub chain_work: BigNum,
}
