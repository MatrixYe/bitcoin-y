//! @Name: script
//!
//! @Date: 2026/4/23 09:55
//!
//! @Author: Matrix.Ye
//!
//! @Description: 脚本系统
//! Script is a stack machine (like Forth) that evaluates a predicate
//! returning a bool indicating valid or not.  There are no loops.
//!
pub mod builder;
pub mod consts;
pub mod error;
pub mod interpreter;
pub mod opcode;
pub mod parser;
pub mod rules;
pub mod verify;

pub type Script = Vec<u8>;

/// 统计脚本中签名检查操作数量，对应原版 `CScript::GetSigOpCount()`。
///
/// 实现逻辑：
/// 1. 按脚本字节流从左到右读取 opcode。
/// 2. 如果 opcode 是 push-data 前缀，就跳过后续被压入的数据字节，避免把数据内容误认为 opcode。
/// 3. 如果 opcode 是 `OP_CHECKSIG` 或 `OP_CHECKSIGVERIFY`，签名操作数加 1。
/// 4. 如果 opcode 是 `OP_CHECKMULTISIG` 或 `OP_CHECKMULTISIGVERIFY`，按原版保守规则加 20。
/// 5. 如果遇到截断的 push-data，说明脚本结构不完整；这里停止统计，格式错误由脚本解析或交易验证的其他部分负责。
///
/// 注意：这个函数只做静态扫描，不执行脚本，也不判断条件分支是否真的会执行。
pub fn count_sig_ops(script: &[u8]) -> usize {
    let mut count = 0;
    // pc 表示当前读取位置，语义等价于原版 CScript::const_iterator pc。
    let mut pc = 0;

    while pc < script.len() {
        let opcode = script[pc];
        pc += 1;

        match opcode {
            // 0x01..=0x4b 表示“接下来 opcode 个字节都是普通数据”。
            // 这些数据不会被执行，所以必须整体跳过。
            0x01..=0x4b => pc = pc.saturating_add(opcode as usize),

            // OP_PUSHDATA1: 后 1 字节表示数据长度，再跳过对应数据。
            0x4c => {
                let Some(size) = script.get(pc).copied() else { break };
                pc = pc.saturating_add(1).saturating_add(size as usize);
            }

            // OP_PUSHDATA2: 后 2 字节小端序表示数据长度，再跳过对应数据。
            0x4d => {
                let Some(bytes) = script.get(pc..pc.saturating_add(2)) else { break };
                let size = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
                pc = pc.saturating_add(2).saturating_add(size);
            }

            // OP_PUSHDATA4: 后 4 字节小端序表示数据长度，再跳过对应数据。
            0x4e => {
                let Some(bytes) = script.get(pc..pc.saturating_add(4)) else { break };
                let size = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
                pc = pc.saturating_add(4).saturating_add(size);
            }

            // OP_CHECKSIG / OP_CHECKSIGVERIFY。
            0xac | 0xad => count += 1,

            // OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY。
            // v0.3.19 这里不读取前置 OP_N 的精确公钥数，而是保守计 20。
            0xae | 0xaf => count += 20,

            // 其他 opcode 不影响签名操作数量。
            _ => {}
        }

        // 如果 push-data 声明的长度超过脚本剩余长度，停止扫描。
        if pc > script.len() {
            break;
        }
    }

    count
}
