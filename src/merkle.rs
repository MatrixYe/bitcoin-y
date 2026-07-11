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
/// 因此放进 merkle.rs 比放在 hash.rs 更合理。
/// hash.rs 应只提供 SHA256、SHA256d、RIPEMD160 等纯哈希原语。
///

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MerkleError {
    #[error("cannot build a merkle proof for an empty tree")]
    EmptyTree,

    #[error("merkle leaf index {index} is out of bounds for {len} leaves")]
    IndexOutOfBounds { index: usize, len: usize },
}

/// 默克尔树
pub struct MerkleTree {
    levels: Vec<Vec<Uint256>>,
}

/// 默克尔路径证明。
///
/// 证明不需要保存整棵树，只需要：
///
/// - `tx_index`：目标交易在最底层叶子列表中的位置，用于判断每一层的左右顺序。
/// - `siblings`：从叶子层到根节点方向，每一层与目标节点配对的兄弟哈希。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    tx_index: usize,
    siblings: Vec<Uint256>,
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

/// 为指定交易构造默克尔路径，类似原版 `GetMerkleBranch`。
///
/// 例如叶子为 `[A, B, C, D]`，需要证明 `C`：
///
/// ```text
/// 第一层兄弟节点：D
/// 第二层兄弟节点：Hash(A, B)
///
/// C -> Hash(C, D) -> Hash(Hash(A, B), Hash(C, D)) -> Root
/// ```
///
/// 因此证明只需要保存 `[D, Hash(A, B)]` 和 `C` 的原始索引 `2`。
pub fn build_merkle_proof(txids: &[Uint256], tx_index: usize) -> Result<MerkleProof, MerkleError> {
    // 空树没有可以证明的叶子节点
    if txids.is_empty() {
        return Err(MerkleError::EmptyTree);
    }
    // 目标索引必须指向一个真实交易
    if tx_index >= txids.len() {
        return Err(MerkleError::IndexOutOfBounds {
            index: tx_index,
            len: txids.len(),
        });
    }

    let mut layer = txids.to_vec();
    // index 会随着树层上升不断转换为父节点索引
    let mut index = tx_index;
    // 按照“叶子层 -> 根节点”的顺序保存每一层的兄弟节点
    let mut siblings = Vec::new();

    while layer.len() > 1 {
        // Bitcoin Merkle Tree 每层节点数为奇数时，复制最后一个节点与自身配对
        if layer.len() % 2 == 1 {
            let last = *layer.last().expect("layer is not empty");
            layer.push(last);
        }

        // 同一对节点的索引最低位互为 0/1：
        // 偶数节点 i 的兄弟是 i + 1，奇数节点 i 的兄弟是 i - 1。
        // 异或 1 可以同时表达这两种情况：0^1=1、1^1=0、2^1=3、3^1=2。
        siblings.push(layer[index ^ 1]);

        // 两两哈希，构造父层。
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks_exact(2) {
            next.push(hash_pair(pair[0], pair[1]));
        }

        layer = next;
        // 每两个子节点对应一个父节点，因此父层索引等于当前索引除以 2。
        index >>= 1;
    }

    Ok(MerkleProof { tx_index, siblings })
}

/// 验证默克尔路径，类似原版 `CheckMerkleBranch`。
///
/// 从目标 `txid` 开始，依次与证明中的兄弟节点组合并重新计算父节点。
/// 最终计算结果与区块头中的 Merkle Root 相同，则证明有效。
pub fn verify_merkle_proof(txid: Uint256, proof: &MerkleProof, expected_root: Uint256) -> bool {
    let mut hash = txid;
    let mut index = proof.tx_index;

    for sibling in &proof.siblings {
        // 索引最低位表示当前节点在这一对中的位置：
        // 0 表示左节点，执行 Hash(current, sibling)
        // 1 表示右节点，执行 Hash(sibling, current)
        // 拼接顺序不能交换，否则会得到不同的父节点哈希。
        hash = match index & 1 {
            0 => hash_pair(hash, *sibling),
            _ => hash_pair(*sibling, hash),
        };

        // 上升到父层，继续使用下一层兄弟节点
        index >>= 1;
    }

    // 重建出的根必须与预期 Merkle Root 完全一致
    hash == expected_root
}

// 拼接两个uint256,组成一个[u8;64],进行sha256d 哈希，得到一个新的[u8;32] 转化成Uint256
fn hash_pair(h1: Uint256, h2: Uint256) -> Uint256 {
    let mut connect = [0x0u8; 64];
    connect[..32].copy_from_slice(&h1.to_bytes());
    connect[32..].copy_from_slice(&h2.to_bytes());
    Uint256::from_bytes(sha256d(&connect))
}
