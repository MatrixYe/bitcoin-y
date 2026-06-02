/// @Name: miner
///
/// @Date: 2026/6/2 16:33
///
/// @Author: Matrix.Ye
///
/// @Description: null
use crate::block::Block;


/// 拓展nonce搜索空间，重构coinbase
/// ```cpp
/// void IncrementExtraNonce(CBlock *pblock, CBlockIndex *pindexPrev, unsigned int &nExtraNonce, int64 &nPrevTime) {
///     // Update nExtraNonce
///     int64 nNow = max(pindexPrev->GetMedianTimePast() + 1, GetAdjustedTime());
///     if (++nExtraNonce >= 0x7f && nNow > nPrevTime + 1) {
///         nExtraNonce = 1;
///         nPrevTime = nNow;
///     }
///     pblock->vtx[0].vin[0].scriptSig = CScript() << pblock->nBits << CBigNum(nExtraNonce);
///     pblock->hashMerkleRoot = pblock->BuildMerkleTree();
/// }
/// ```
pub fn increment_extra_nonce(p_block: &Block) {



}