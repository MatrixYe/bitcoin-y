use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScriptError {
    /// 非法指令
    #[error("invalid opcode: 0x{0:02x}")]
    InvalidOpcode(u8),

    /// 失效的指令
    #[error("disabled opcode: 0x{0:02x}")]
    DisabledOpcode(u8),

    /// 脚本意外中断
    #[error("unexpected end of script")]
    UnexpectedEndOfScript,

    /// 错误的数据长度
    #[error("invalid pushdata length")]
    InvalidPushDataLength,

    /// 脚本过大
    #[error("script size exceeds limit")]
    ScriptTooLarge,

    /// 操作码过多
    #[error("too many opcodes")]
    TooManyOps,

    /// 栈下溢出
    #[error("stack underflow")]
    StackUnderflow,

    /// 栈溢出
    #[error("stack overflow")]
    StackOverflow,

    /// 脚本元素过多
    #[error("script element too large")]
    ElementTooLarge,

    /// 验证失败
    #[error("verify failed")]
    VerifyFailed,

    /// 验证失败
    #[error("equalverify failed")]
    EqualVerifyFailed,

    /// 签名检测失败
    #[error("checksig failed")]
    CheckSigFailed,

    /// 不支持的脚本格式
    #[error("unsupported script form")]
    UnsupportedScriptForm,

    /// 其他
    #[error("{0}")]
    OtherError(String),
}
