use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScriptError {
    /// 非法指令
    #[error("invalid opcode: 0x{0:02x}")]
    InvalidOpcode(u8),

    /// 被禁用的指令
    #[error("disabled opcode: 0x{0:02x}")]
    DisabledOpcode(u8),

    /// 保留指令
    #[error("reserved opcode: 0x{0:02x}")]
    ReservedOpcode(u8),

    /// 脚本意外中断
    #[error("unexpected end of script")]
    UnexpectedEndOfScript,

    /// 条件控制结构不匹配
    #[error("unbalanced conditional control flow")]
    UnbalancedConditional,

    /// 脚本结束时仍存在未关闭的条件控制块
    #[error("unclosed conditional control flow")]
    UnclosedConditional,

    /// OP_RETURN 主动使脚本失败
    #[error("op return")]
    OpReturn,

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
    #[error("script size exceeds limit:max {max}, actual {actual}")]
    ScriptTooLarge { max: usize, actual: usize },

    /// 操作码过多
    #[error("too many opcodes")]
    TooManyOps,

    /// 栈下溢出
    #[error("stack underflow")]
    StackUnderflow,

    /// 栈溢出
    #[error("stack overflow")]
    StackOverflow,

    /// 栈索引非法
    #[error("invalid stack index: index {index}, stack length {len}")]
    InvalidStackIndex { index: i64, len: usize },

    /// 字节串截取参数非法(个人新增的)
    #[error("invalid splice argument")]
    InvalidSpliceArgument,

    /// 单个脚本元素的长度过大，最大520，实际超过
    #[error("script element too large: max {max}, actual {actual}")]
    ElementTooLarge { max: usize, actual: usize },

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

    #[error("invalid SmallInt: {n}")]
    InvalidSmallInt { n: i32 },

    /// 脚本数字过大
    ///  参考 v0.3.19 CastToBigNum：普通数值操作最多接受 4 字节。
    #[error("script number overflow: max {max} bytes, actual {actual} bytes")]
    ScriptNumOverflow { max: usize, actual: usize },

    /// 其他
    #[error("{0}")]
    OtherError(String),

    /// 数字运算溢出
    #[error("numeric overflow")]
    NumericOverflow,

    /// 除数为 0
    #[error("division by zero")]
    DivisionByZero,

    /// 非法移位参数(新加的)
    #[error("invalid numeric shift: {shift}")]
    InvalidNumericShift { shift: String },

    /// 非法的类型转化
    #[error("Illegal data type conversion")]
    InvalidDataTypeCast,
}
