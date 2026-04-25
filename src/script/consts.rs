/// 参考最新比特币，脚本系统相关常量`src/script/script.h`。

/// 单个栈元素最多能压入的字节数。
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// 单个脚本中非 push 操作的最大数量。
pub const MAX_OPS_PER_SCRIPT: usize = 201;

/// 多签脚本中允许的最大公钥数量。
pub const MAX_PUBKEYS_PER_MULTISIG: usize = 20;

/// 基于 OP_CHECKSIGADD 的脚本中允许的最大公钥数量。
///
/// 这个限制来自 BIP342 中的栈大小限制。
pub const MAX_PUBKEYS_PER_MULTI_A: usize = 999;

/// 脚本最大字节长度。
pub const MAX_SCRIPT_SIZE: usize = 10_000;

/// 脚本解释器主栈允许的最大元素数量。
pub const MAX_STACK_SIZE: usize = 1_000;

/// nLockTime 的阈值。
///
/// 小于该值时按区块高度解释，否则按 UNIX 时间戳解释。
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// 最大 nLockTime。
///
/// nLockTime 表示最后一个无效时间，因此这个值通常永远不会有效，
/// 除非禁用了 locktime 检查。
pub const LOCKTIME_MAX: u32 = 0xffff_ffff;

/// 输入 annex 的标签。
///
/// 当交易输入至少有两个 witness 元素，且最后一个元素首字节为 0x50 时，
/// 该最后元素称为 annex，并拥有独立于脚本的含义。
pub const ANNEX_TAG: u8 = 0x50;

/// 每个通过验证的签名消耗的验证权重。
///
/// 仅用于 Tapscript，见 BIP342。
pub const VALIDATION_WEIGHT_PER_SIGOP_PASSED: i64 = 50;

/// 加到 witness 大小上的验证权重预算。
///
/// 仅用于 Tapscript，见 BIP342。
pub const VALIDATION_WEIGHT_OFFSET: i64 = 50;
