use crate::bignum::BigNum;
use crate::uint256::Uint256;

/// @Name: chain
///
/// @Date: 2026/6/18 16:14
///
/// @Author: Matrix.Ye
///
/// @Description: null

/// 区块链是一种树状结构，起始点是创世区块，位于根部， 每个区块都有可能有多个成为下一区块的候选者。pprev 和 pnext 构成了贯穿主链/最长链的路径。
/// 一个区块索引可能有多个 pprev 指向它，但 pnext 只会指向最长分支，或者如果该区块不属于最长链，则 pnext 会指向空值。//
/// ```cpp
///  class CBlockIndex
///  {
///  public:
///      const uint256* phashBlock;
///      CBlockIndex* pprev;
///      CBlockIndex* pnext;
///      unsigned int nFile;
///      unsigned int nBlockPos;
///      int nHeight;
///      CBigNum bnChainWork;
///
///      // block header
///      int nVersion;
///      uint256 hashMerkleRoot;
///      unsigned int nTime;
///      unsigned int nBits;
///      unsigned int nNonce;}
/// ```
pub struct BlockIndex {
    // 哈希
    hash: Uint256,
    // 双向链表
    pub prev: Option<Uint256>,
    pub next: Option<Uint256>,
    pub height: u32,
    pub chain_work: BigNum, // 核心数据:累计工作量
    // todo: 可能需要补充本地存储信息

    // block header
    pub version: i32,
    pub prev_block: Uint256,
    pub merkle_root: Uint256,
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl BlockIndex {
    pub fn hash(&self) -> Uint256 {
        self.hash
    }

    pub fn get_work(&self) -> BigNum {
        let bn_target = BigNum::set_compact(self.bits);
        if bn_target <= BigNum::zero() {
            BigNum::ZERO
        } else {
            let a = BigNum::from_u32(1) << 256;
            let b = bn_target + BigNum::from_u32(1);
            a / b
        }
    }

    pub fn check_work(&self) -> bool {
        let bn_target = BigNum::set_compact(self.bits);
        if bn_target <= BigNum::zero() {
            false
        } else {
            self.hash <= bn_target.to_uint256()
        }
    }
}
