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
    pub fn hash(&self) -> Uint256 {
        self.header.block_hash()
    }

    /// 计算区块头的默克尔树根
    pub fn compute_merkle_root(&self) -> Uint256 {
        let txids: Vec<Uint256> = self.txdata.iter().map(|x| x.txid()).collect();
        compute_merkle_root(txids)
    }

    /// 计算此区块的工作量
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
        let (target, negative, overflow) = Uint256::set_compact(self.header.bits);

        match negative || overflow || target.is_zero() {
            true => false,
            false => hash <= target,
        }
    }
}
