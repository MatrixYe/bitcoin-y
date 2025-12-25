use std::io;
use thiserror::Error;

/// 复用错误
#[derive(Error, Debug)]
pub enum CommonError {
    /// IO错误（包装std::io::Error）
    #[error("IO Error:{0}")]
    Io(#[from] io::Error),

    /// 数据解析错误如JSON/TOML/CSV解析失败
    #[error("Parse Error:{0}")]
    Parse(String),

    /// 无效参数错误
    #[error("Invalid Argument:{0}")]
    InvalidArgument(String),

    /// 资源未找到错误
    #[error("Source Not Found:{0}")]
    NotFound(String),

    /// 权限不足错误
    #[error("Permission Denied:{0}")]
    PermissionDenied(String),
}

/// 密钥对错误
#[derive(Error, Debug, PartialEq)]
pub enum KeyPairError {
    // 私钥的长度错误
    #[error("Invalid hex string length: expected 64 characters,but got {0}")]
    InvalidHexLength(u32),

    // 私钥的十六进制字符错误
    #[error("Invalid secret key: not a valid secp256k1 secret key")]
    InvalidSecretKey,
}
