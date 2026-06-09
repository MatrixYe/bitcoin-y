use crate::hash::sha256d;
use crate::uint256::Uint256;
use thiserror::Error;

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

/// 默克尔树
pub struct MerkleTree {
    levels: Vec<Vec<Uint256>>,
}

/// 默克尔路径证明
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    tx_index: usize,
    siblings: Vec<Uint256>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MerkleError {
    #[error("cannot build a merkle proof for an empty tree")]
    EmptyTree,

    #[error("merkle leaf index {index} is out of bounds for {len} leaves")]
    IndexOutOfBounds { index: usize, len: usize },
}

impl MerkleProof {
    pub fn tx_index(&self) -> usize {
        self.tx_index
    }

    pub fn siblings(&self) -> &[Uint256] {
        &self.siblings
    }
}

/// 实现:BuildMerkleTree
/// 通过交易列表，计算默克尔树的根哈希
pub fn compute_merkle_root(mut layer: Vec<Uint256>) -> Uint256 {
    if layer.is_empty() {
        return Uint256::ZERO;
    }
    // 如果只有一条交易Tx，那么直接返回Txid
    if layer.len() == 1 {
        return layer[0];
    }

    // 分层构建默克尔树
    while layer.len() > 1 {
        // 奇数节点，复制最后一个哈希
        if layer.len() % 2 == 1 {
            let last = *layer.last().expect("layer is not empty");
            layer.push(last);
        }

        // 定义新的一层，长度减半
        let mut new_layer: Vec<Uint256> = Vec::with_capacity(layer.len() / 2);
        // 每一层，两两组合再进行double sha256
        for pair in layer.chunks_exact(2) {
            let new_hash = hash_pair(pair[0], pair[1]);
            new_layer.push(new_hash);
        }
        layer = new_layer;
    }
    // merkle tree root
    layer[0]
}

fn hash_pair(h1: Uint256, h2: Uint256) -> Uint256 {
    let mut connect = [0x0u8; 64];
    connect[..32].copy_from_slice(&h1.to_bytes());
    connect[32..].copy_from_slice(&h2.to_bytes());
    Uint256::from_bytes(sha256d(&connect))
}

/// 提供默克尔路径，类似实现 `GetMerkleBranch`
pub fn build_merkle_proof(txids: &[Uint256], tx_index: usize) -> Result<MerkleProof, MerkleError> {
    if txids.is_empty() {
        return Err(MerkleError::EmptyTree);
    }
    if tx_index >= txids.len() {
        return Err(MerkleError::IndexOutOfBounds {
            index: tx_index,
            len: txids.len(),
        });
    }

    let mut layer = txids.to_vec();
    let mut index = tx_index;
    let mut siblings = Vec::new(); // 兄弟节点

    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            let last = *layer.last().expect("layer is not empty");
            layer.push(last);
        }

        siblings.push(layer[index ^ 1]);

        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks_exact(2) {
            next.push(hash_pair(pair[0], pair[1]));
        }

        layer = next;
        index >>= 1;
    }

    Ok(MerkleProof { tx_index, siblings })
}

/// 验证默克尔路径，类似实现 `CheckMerkleBranch`
pub fn verify_merkle_proof(txid: Uint256, proof: &MerkleProof, expected_root: Uint256) -> bool {
    let mut hash = txid;
    let mut index = proof.tx_index;

    for sibling in &proof.siblings {
        hash = match index & 1 {
            0 => hash_pair(hash, *sibling),
            _ => hash_pair(*sibling, hash),
        };
        index >>= 1;
    }

    hash == expected_root
}
