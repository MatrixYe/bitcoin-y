use ripemd::Ripemd160;
/// @Name: utils
///
/// @Date: 2026/4/13 21:32
///
/// @Author: Matrix.Ye
///
/// @Description: 工具函数
use sha2::{Digest, Sha256};

/// 计算 SHA256 哈希
///
/// # 参数
///
/// * `data` - 要计算哈希的数据
///
/// # 返回值
///
/// * `[u8; 32]` - SHA256 哈希结果 (32个字节)
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(data);
    hash.into()
}

///
///
/// # Arguments
///
/// * `data`: 数据
///
/// returns: [u8; 20]
///
/// # Examples
///
/// ```
///
/// ```
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let hash = Ripemd160::digest(data);
    hash.into()
}

///
///
/// # Arguments
///
/// * `data`:
///
/// returns: [u8; 20]
///
/// # Examples
///
/// ```
///
/// ```
pub fn sha256_and_ripemd160(data: &[u8]) -> [u8; 20] {
    let hash = sha256(data);
    ripemd160(&hash)
}

/// 计算双重 SHA256 哈希 (SHA256(SHA256(data)))
///
/// 比特币中使用双重 SHA256 来计算交易 ID 和区块哈希
///
/// # 参数
///
/// * `data` - 要计算哈希的数据
///
/// # 返回值
///
/// * `[u8; 32]` - 双重 SHA256 哈希结果 (32字节)
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first_hash = Sha256::digest(data);
    let second_hash = Sha256::digest(first_hash);
    second_hash.into()
}
