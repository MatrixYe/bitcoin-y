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

    #[error("invalid pushdata Direct,expected in [0x01,0x4b],actual {actual}")]
    InvalidPushDataDirect { actual: u8 },

    /// 数据长度不匹配
    #[error("{kind} pushdata length mismatch: expected {expected}, actual {actual}")]
    PushDataLengthMismatch {
        kind: &'static str,
        expected: usize,
        actual: usize,
    },

    /// 数据长度过大
    #[error("{kind} pushdata length too large: max {max}, actual {actual}")]
    PushDataLengthTooLarge {
        kind: &'static str,
        max: usize,
        actual: usize,
    },

    /// 数据长度过小
    #[error("{kind} pushdata length too small: min {min}, actual {actual}")]
    PushDataLengthTooSmall {
        kind: &'static str,
        min: usize,
        actual: usize,
    },

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
