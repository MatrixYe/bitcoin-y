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
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(data);
    hash.into()
}

/// 计算 RIPEMD160 哈希
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let hash = Ripemd160::digest(data);
    hash.into()
}

/// 先经过sha256，再经过ripemd160,在地址生成的时候使用
pub fn sha256_and_ripemd160(data: &[u8]) -> [u8; 20] {
    let hash = sha256(data);
    let ripemd160 = Ripemd160::digest(hash);
    ripemd160.into()
}

/// 计算双重 SHA256 哈希 (SHA256(SHA256(data)))
/// 交易ID和区块哈希，以及默克尔树
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first_hash = Sha256::digest(data);
    let second_hash = Sha256::digest(first_hash);
    second_hash.into()
}
