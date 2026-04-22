// @Name: utils
// @Date: 2026/4/13 21:32
// @Author: Matrix.Ye
// @Description: 工具函数

use crate::hash::{hash160, sha256 as hash_sha256, sha256d};
use ripemd::{Digest, Ripemd160};

/// 计算 SHA256 哈希
pub fn sha256(data: &[u8]) -> [u8; 32] {
    hash_sha256(data)
}

/// 计算 RIPEMD160 哈希
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let hash = Ripemd160::digest(data);
    hash.into()
}

/// 先经过sha256，再经过ripemd160,在地址生成的时候使用
pub fn sha256_and_ripemd160(data: &[u8]) -> [u8; 20] {
    hash160(data)
}

/// 计算双重 SHA256 哈希 (SHA256(SHA256(data)))
/// 交易ID和区块哈希，以及默克尔树
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    sha256d(data).0
}
