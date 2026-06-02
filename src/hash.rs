// Digest 提供统一哈希接口
use crate::errors::CError;
use crate::uint256::Uint256;
use hex::FromHexError;
use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::{Digest, Sha256};

//------------------------------- 哈希计算 -------------------------------//

/// 哈希计算 sha1：data -> sha1(data)
pub fn sha1(data: &[u8]) -> [u8; 20] {
    Sha1::digest(data).into()
}

/// 哈希计算 sha256: data -> sha256(data)
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// 哈希计算 sha256d: data -> sha256(sha256(data))
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let v1: [u8; 32] = Sha256::digest(data).into();
    let v2: [u8; 32] = Sha256::digest(v1).into();
    v2
}

/// 哈希计算 hash160: data -> ripemd160(sha256(data))
pub fn hash160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(sha256(data)).into()
}

/// 哈希计算 ripemd160：data -> ripemd160(data)
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(data).into()
}

fn invalid_hash_hex(error: FromHexError) -> CError {
    CError::Parse(format!("Invalid hash hex: {error}"))
}

/// 构建默克尔树根
pub fn make_merkle_root(mut layer: Vec<[u8; 32]>) -> [u8; 32] {
    if layer.len() == 0 {
        return Uint256::ZERO.to_bytes();
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
            bytes[..32].copy_from_slice(&pair[0]);
            bytes[32..].copy_from_slice(&pair[1]);
            // 计算double hash,添加
            next.push(sha256d(&bytes));
        }
        layer = next;
    }
    layer[0]
}
