use crate::errors::CError;
use crate::script::CScript;
use crate::uint256::Uint256;
use crate::utils::double_sha256;
// 交易类型
pub enum TransactionType {
    Normal,
    Coinbase,
}

// 默克尔根哈希
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MerkleHash(pub [u32; 8]);

pub type BlockHash = Uint256;
// 交易
#[derive(Debug, Clone)]
pub struct CTransaction {
    n_version: u8,
    vin: Vec<CTxIn>,
    vout: Vec<CTxOut>,
    n_lock_time: u32,
}

// 交易输出位置
#[derive(Debug, Clone)]
pub struct COutPoint {
    hash: Uint256,
    n: i32,
}

impl COutPoint {
    pub fn set_null(&mut self) {
        self.hash = Uint256::default();
        self.n = -1;
    }
    pub fn is_null(&self) -> bool {
        self.hash == Uint256::default() && self.n == -1
    }
}

// 交易输入
#[derive(Debug, Clone)]
pub struct CTxIn {
    preout: COutPoint,
    script_sig: CScript,
    n_sequence: u32,
}

// 交易输出
#[derive(Debug, Clone)]
pub struct CTxOut {
    value: u64,
    script_pub_key: CScript,
}

//todo:不要用引用，直接存交易哈希 [u8;32]彻底告别生命周期烦恼。
pub struct CInPoint<'a> {
    ptx: &'a CTransaction,
    n: u32,
}

pub struct MerkleTx {
    base: CTransaction,
    hash_block: Uint256,              //所在区块哈希
    n_index: u32,                     //在区块中的索引
    v_merkle_branch: Vec<MerkleHash>, //默克尔分支
    f_merkle_verified: bool,          //默克尔验证状态
}

impl CTransaction {
    /// 判断是否是coinbase交易
    pub fn is_coinbase(&self) -> bool {
        self.vin.len() == 1 && self.vin[0].preout.is_null()
    }

    /// 获取交易的哈希值
    pub fn get_hash(&self) -> Uint256 {
        // Uint256(double_sha256(self.serialize().as_slice()))
        double_sha256(self.serialize().as_slice()).into()
    }
    /// 将交易序列化为比特币原生格式
    ///
    /// 比特币交易序列化格式:
    /// - version: 4字节 (小端序)
    /// - tx_in count: 变长整数 (CompactSize)
    /// - tx_in: 输入列表
    ///   - previous_output hash: 32字节
    ///   - previous_output n: 4字节 (小端序)
    ///   - script bytes: 变长整数
    ///   - signature script: 变长
    ///   - sequence: 4字节 (小端序)
    /// - tx_out count: 变长整数 (CompactSize)
    /// - tx_out: 输出列表
    ///   - value: 8字节 (小端序)
    ///   - script bytes: 变长整数
    ///   - script pubkey: 变长
    /// - lock_time: 4字节 (小端序)
    ///
    /// # 返回值
    ///
    /// * `Vec<u8>` - 序列化后的字节数组
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        unimplemented!();
        buffer
    }

    // 检查交易是否有效，无上下文依赖
    pub fn check_transaction(&self) -> Result<bool, CError> {
        if self.vin.is_empty() && self.vout.is_empty() {
            return Err(CError::InvalidTransaction(
                "CTransaction::CheckTransaction() : vin or vout empty".to_string(),
            ));
        }
        if self.is_coinbase() {
            if self.vin[0].script_sig.len() < 2 || self.vin[0].script_sig.len() > 100 {
                return Err(CError::InvalidTransaction(
                    "CTransaction::CheckTransaction() : coinbase script size error".to_string(),
                ));
            }
        } else {
            if self.vin.iter().any(|txin| txin.preout.is_null()) {
                return Err(CError::InvalidTransaction(
                    "CTransaction::CheckTransaction() : prevout is null".to_string(),
                ));
            }
        }
        Ok(true)
    }
}
//noinspection GrazieInspection
