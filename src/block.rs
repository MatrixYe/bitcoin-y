use crate::tx::CTransaction;
use crate::uint256::Uint256;
use crate::utils::{compact_to_target, double_sha256};
use log;
//class CBlock {
// public:
//   // header
//   int nVersion;
//   uint256 hashPrevBlock;
//   uint256 hashMerkleRoot;
//   unsigned int nTime;
//   unsigned int nBits;
//   unsigned int nNonce;
//
//   // network and disk
//   vector<CTransaction> vtx;
//
//   // memory only
//   mutable vector<uint256> vMerkleTree;

/// 区块头哈希
pub type BlockHash = Uint256;

/// 默克尔树节点哈希
pub type MerkleHash = Uint256;

/// 比特币区块结构体
///
/// 包含区块头(header)和交易列表(body)
/// 区块头用于工作量证明计算,交易列表包含该区块的所有交易
#[derive(Debug, Clone)]
pub struct CBlock {
    // === 区块头 (80字节) ===
    /// 区块版本号
    n_version: i32,

    /// 前一个区块的哈希值
    prev_block_hash: BlockHash,

    /// Merkle 根哈希(所有交易的哈希根)
    merkle_root_hash: MerkleHash,

    /// 时间戳(Unix纪元时间)
    n_time: u32,

    /// 难度目标(压缩格式)
    n_bits: u32,

    /// 工作量证明的随机数
    n_nonce: u32,

    // === 区块体 ===
    /// 交易列表(包含coinbase交易)
    vtx: Vec<CTransaction>,

    // === 内存缓存字段(不序列化到磁盘/网络) ===
    /// 默克尔树节点缓存(用于快速验证)
    /// mutable: 可变字段,在const方法中也可以修改
    v_merkle_tree: Vec<MerkleHash>,
}

impl CBlock {
    /// 序列化区块头为比特币原生格式(80字节)
    ///
    /// 比特币区块头序列化格式:
    /// - version: 4字节 (小端序)
    /// - prev_block_hash: 32字节
    /// - merkle_root_hash: 32字节
    /// - time: 4字节 (小端序)
    /// - bits: 4字节 (小端序)
    /// - nonce: 4字节 (小端序)
    ///
    /// # 返回值
    ///
    /// * `Vec<u8>` - 80字节的区块头序列化数据
    ///
    pub fn serialize_header(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(80);

        // 1. 序列化 version (4字节, 小端序)
        buffer.extend_from_slice(&self.n_version.to_le_bytes());

        // 2. 序列化 prev_block_hash (32字节)
        buffer.extend_from_slice(&self.prev_block_hash.value());

        // 3. 序列化 merkle_root_hash (32字节)
        buffer.extend_from_slice(&self.merkle_root_hash.value());

        // 4. 序列化 time (4字节, 小端序)
        buffer.extend_from_slice(&self.n_time.to_le_bytes());

        // 5. 序列化 bits (4字节, 小端序)
        buffer.extend_from_slice(&self.n_bits.to_le_bytes());

        // 6. 序列化 nonce (4字节, 小端序)
        buffer.extend_from_slice(&self.n_nonce.to_le_bytes());

        buffer
    }

    // 计算区块哈希
    pub fn get_hash(&self) -> BlockHash {
        let value = double_sha256(self.serialize_header().as_slice());
        Uint256::from_bytes(value)
        // unimplemented!()
    }

    // 检查 PoW
    pub fn check_proof_of_work(&self) -> bool {
        // 1. 从 n_bits 解压缩得到目标值
        let target = match compact_to_target(self.n_bits) {
            Some(t) => t,
            None => {
                log::error!("Invalid target value");
                return false;
            } // 无效的目标值
        };

        // 2. 计算区块哈希
        let block_hash: BlockHash = self.get_hash();
        let target_hash = Uint256::from_bytes(target);

        // 3. 比较哈希是否小于目标值
        block_hash < target_hash
    }

    // 构建默克尔树
    pub fn build_merkle_tree(&mut self) {
        unimplemented!()
    }
}
