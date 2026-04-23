use thiserror::Error;

use crate::script::error::ScriptError;

#[derive(Error, Debug, PartialEq)]
pub enum CError {
    /// IO错误
    #[error("IO Error:{0}")] //不要包装std::io::Error，因为不支持PartialEq
    IO(String),

    /// 数据解析错误如JSON/TOML/CSV解析失败
    #[error("Parse Error:{0}")]
    Parse(String),

    /// 无效参数错误
    #[error("Invalid Argument:{0}")]
    InvalidArgument(String),

    #[error("Unknown Error")]
    UnknowError(),

    /// 资源未找到错误
    #[error("Source Not Found:{0}")]
    NotFound(String),

    /// 权限不足错误
    #[error("Permission Denied:{0}")]
    PermissionDenied(String),

    // 长度错误
    #[error("Invalid hex string length: expected {0} characters,but got {1}")]
    InvalidHexLength(u32, u32),

    // 私钥的十六进制字符错误
    #[error("Invalid secret key: not a valid secp256k1 secret key")]
    InvalidSecretKey,

    #[error("Invalid transaction:{0}")]
    InvalidTransaction(String),

    /// 脚本执行错误
    #[error("Script Error:{0}")]
    Script(#[from] ScriptError),
}
