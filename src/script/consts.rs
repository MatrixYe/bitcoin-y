/// @Name: script/consts
///
/// @Date: 2026/4/9 03:41
///
/// @Author: Matrix.Ye
///
/// @Description: 与脚本相关的产量，参考[比特币脚本Wiki](https://en.bitcoin.it/wiki/Script)

/// 脚本最大字节长度。
pub const MAX_SCRIPT_SIZE: usize = 10_000;

/// 单个栈元素最大字节长度。
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// 单个脚本允许执行的最大 opcode 数量。
pub const MAX_OPS_PER_SCRIPT: usize = 201;

/// 解释器主栈和备用栈合计的最大元素数量。
pub const MAX_STACK_SIZE: usize = 1_000;
