use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum KeyPairError {
    // 私钥的长度错误
    #[error("Invalid hex string length: expected 64 characters,but got {0}")]
    InvalidHexLength(u32),

    // 私钥的十六进制字符错误
    #[error("Invalid secret key: not a valid secp256k1 secret key")]
    InvalidSecretKey,
}
