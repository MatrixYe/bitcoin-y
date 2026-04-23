use std::fmt;

use hex::FromHexError;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::errors::CError;
use crate::uint256::Uint256;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    pub const fn zero() -> Self {
        Self([0; 32])
    }

    pub fn from_display_hex(hex: &str) -> Result<Self, CError> {
        let hex = hex.trim_start_matches("0x").trim_start_matches("0X");
        if hex.len() != 64 {
            return Err(CError::InvalidHexLength(64, hex.len() as u32));
        }

        let mut display_bytes = [0u8; 32];
        hex::decode_to_slice(hex, &mut display_bytes).map_err(invalid_hash_hex)?;
        display_bytes.reverse();
        Ok(Self(display_bytes))
    }

    pub fn to_display_hex(self) -> String {
        let mut display_bytes = self.0;
        display_bytes.reverse();
        hex::encode(display_bytes)
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_display_hex())
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_display_hex())
    }
}

/// u8 => Hash256
impl From<[u8; 32]> for Hash256 {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

/// Hash256 => u8
impl From<Hash256> for [u8; 32] {
    fn from(value: Hash256) -> Self {
        value.0
    }
}

impl From<Hash256> for Uint256 {
    fn from(value: Hash256) -> Self {
        Uint256::from(value.0)
    }
}

impl From<Uint256> for Hash256 {
    fn from(value: Uint256) -> Self {
        Self(value.to_bytes())
    }
}

/// 一次sha256
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// 两次哈希，sha256 * sha256
pub fn sha256d(data: &[u8]) -> Hash256 {
    Hash256(sha256(&sha256(data)))
}

/// 先sha256 再ripemd160,在生成地址的时候需要使用
pub fn hash160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(sha256(data)).into()
}

fn invalid_hash_hex(error: FromHexError) -> CError {
    CError::Parse(format!("Invalid hash hex: {error}"))
}

/// 构建默克尔树根
pub fn make_merkle_root(mut layer: Vec<Hash256>) -> Hash256 {
    if layer.len() == 0 {
        return Hash256::zero();
    }
    if layer.len() == 1 {
        return layer[0];
    }
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            // 奇数项,复制最后一个元素添加到尾部
            let last = layer[layer.iter().len() - 1];
            layer.push(last);
        }
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks(2) {
            // 切片，大小2
            let mut bytes = [0u8; 64];
            // 拼接32*2=64
            bytes[..32].copy_from_slice(&pair[0].0);
            bytes[32..].copy_from_slice(&pair[1].0);
            // 计算double hash,添加
            next.push(sha256d(&bytes));
        }
        layer = next;
    }
    layer[0]
}
