use crate::hash::sha256d;
use crate::uint256::Uint256;

/// @Name: merkle
///
/// @Date: 2026/6/9 17:53
///
/// @Author: Matrix.Ye
///
/// @Description:
/// Merkle 不只是哈希辅助函数，后续还会包含：Merkle Root 构造 、Merkle Branch/Proof 构造、 Merkle 路径验证 交易在区块中的包含性证明
/// 节点右方向信息 可能的 Merkle Tree 缓存
/// 原版也有类似职责：
///
/// - BuildMerkleTree
/// - GetMerkleBranch
/// - CheckMerkleBranch
///
/// 因此放进 merkle.rs 比放在 hash.rs 更合理。hash.rs 应只提供 SHA256、SHA256d、RIPEMD160 等纯哈希原语。
///
///

/// 默克尔树
pub struct MerkleTree {
    levels: Vec<Vec<Uint256>>,
}

/// 默克尔路径证明
pub struct MerkleProof {
    tx_index: usize,
    siblings: Vec<Uint256>,
}

/// 实现:BuildMerkleTree
/// 通过交易列表，计算默克尔树的根哈希
pub fn compute_merkle_root(mut layer: Vec<Uint256>) -> Uint256 {
    if layer.is_empty() {
        return Uint256::ZERO;
    }
    if layer.len() == 1 {
        return layer[0];
    }
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            let last = *layer.last().expect("layer is not empty");
            layer.push(last);
        }
        let mut new_layer: Vec<Uint256> = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks_exact(2) {
            let new_hash = hash_pair(pair[0], pair[1]);
            new_layer.push(new_hash);
        }
        layer = new_layer;
    }
    layer[0]
}

fn hash_pair(h1: Uint256, h2: Uint256) -> Uint256 {
    let mut connect = [0x0u8; 64];
    connect[..32].copy_from_slice(&h1.to_bytes());
    connect[32..].copy_from_slice(&h2.to_bytes());
    Uint256::from_bytes(sha256d(&connect))
}

/// 提供默克尔路径，类似实现 `GetMerkleBranch`
pub fn build_merkle_proof() {
    unimplemented!()
}

/// 验证默克尔路径，类似实现 `CheckMerkleBranch`
pub fn verify_merkle_proof() {
    unimplemented!()
}
