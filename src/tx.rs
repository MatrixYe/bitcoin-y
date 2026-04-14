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
pub struct MerkleHash(pub [u8; 32]);

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
    // 判断是否是coinbase交易
    pub fn is_coinbase(&self) -> bool {
        self.vin.len() == 1 && self.vin[0].preout.is_null()
    }
    pub fn hash(&self) -> Uint256 {
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
        let mut buffer = Vec::new();

        // 1. 序列化 version (4字节, 小端序)
        buffer.extend_from_slice(&(self.n_version as u32).to_le_bytes());

        // 2. 序列化输入数量 (CompactSize 变长整数)
        buffer.extend(write_compact_size(self.vin.len()));

        // 3. 序列化每个输入
        for txin in &self.vin {
            // 3.1 previous_output hash (32字节)
            buffer.extend_from_slice(&txin.preout.hash.value());

            // 3.2 previous_output n (4字节, 小端序)
            buffer.extend_from_slice(&txin.preout.n.to_le_bytes());

            // 3.3 script_sig 长度 (CompactSize)
            buffer.extend(write_compact_size(txin.script_sig.len()));

            // 3.4 script_sig 内容
            buffer.extend_from_slice(&txin.script_sig);

            // 3.5 sequence (4字节, 小端序)
            buffer.extend_from_slice(&txin.n_sequence.to_le_bytes());
        }

        // 4. 序列化输出数量 (CompactSize)
        buffer.extend(write_compact_size(self.vout.len()));

        // 5. 序列化每个输出
        for txout in &self.vout {
            // 5.1 value (8字节, 小端序)
            buffer.extend_from_slice(&txout.value.to_le_bytes());

            // 5.2 script_pub_key 长度 (CompactSize)
            buffer.extend(write_compact_size(txout.script_pub_key.len()));

            // 5.3 script_pub_key 内容
            buffer.extend_from_slice(&txout.script_pub_key);
        }

        // 6. 序列化 lock_time (4字节, 小端序)
        buffer.extend_from_slice(&self.n_lock_time.to_le_bytes());

        buffer
    }

    // 检查交易是否有效，无上下文依赖
    pub fn check_transaction(&self) -> Result<bool, CError> {
        if self.vin.is_empty() && self.vout.is_empty() {
            return Err(CError::InvalidTransaction(
                "CTransaction::CheckTransaction() : vin or vout empty".to_string(),
            ));
        }
        // 检查是否有负值,由于类型限制，这样的比较毫无意义，中本聪用c++写才需要判断正负
        // if self.vout.iter().any(|txout| txout.value < 0) {
        //     return Err(CError::InvalidTransaction(
        //         "CTransaction::CheckTransaction() : txout value negative".to_string(),
        //     ));
        // }

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
/// CompactSize 变长整数编码
///
/// 比特币使用的变长整数编码规则:
/// - 0-252: 直接编码为1字节
/// - 253-0xFFFF: 0xFD + 2字节 (小端序)
/// - 0x10000-0xFFFFFFFF: 0xFE + 4字节 (小端序)
/// - 0x100000000-: 0xFF + 8字节 (小端序)
///
fn write_compact_size(value: usize) -> Vec<u8> {
    if value < 0xFD {
        vec![value as u8]
    } else if value <= 0xFFFF {
        let mut result = vec![0xFD];
        result.extend_from_slice(&(value as u16).to_le_bytes());
        result
    } else if value <= 0xFFFFFFFF {
        let mut result = vec![0xFE];
        result.extend_from_slice(&(value as u32).to_le_bytes());
        result
    } else {
        let mut result = vec![0xFF];
        result.extend_from_slice(&(value as u64).to_le_bytes());
        result
    }
}
