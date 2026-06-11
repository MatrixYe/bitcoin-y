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

