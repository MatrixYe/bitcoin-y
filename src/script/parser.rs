use crate::script::opcode::{OpCode, PushOp};
use crate::script::ScriptError;

use std::fmt;

/// @Name: parser.rs
///
/// @Date: 2026/4/9 03:41
///
/// @Author: Matrix.Ye
///
/// @Description: 脚本解析器
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptToken {
    //表示一个具名 opcode，比如 OP_DUP、OP_1、OP_CHECKSIG。
    Command(OpCode),

    //表示 parser 已经从脚本字节流里取出一段 payload bytes，执行器只需要把它压栈。
    Data { kind: PushDataKind, bytes: Vec<u8> },
}

// 数据压栈方式
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushDataKind {
    Direct(u8), // 直接压栈，
    PushData1,  // 下1个字节表示即将压栈的数据长度，最大u8::MAX
    PushData2,  // 下2个字节表示即将压栈的数据长度，最大u16::MAX
    PushData4,  // 下4个字节表示即将压栈的数据长度，最大u32::MAX
}

impl fmt::Display for PushDataKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct(n) => write!(f, "Direct({n})"),
            Self::PushData1 => f.write_str("OP_PUSHDATA1"),
            Self::PushData2 => f.write_str("OP_PUSHDATA2"),
            Self::PushData4 => f.write_str("OP_PUSHDATA4"),
        }
    }
}

impl fmt::Display for ScriptToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Command(opcode) => write!(f, "{opcode}"),
            Self::Data { kind, bytes } => {
                write!(f, "{kind} len={} bytes=0x{}", bytes.len(), hex::encode(bytes))
            }
        }
    }
}

///
/// 解码： 字节流 => 结构化数据
/// # Arguments
///
/// * `script`: 脚本字节流
///
/// returns: Result<Vec<ScriptToken>, ScriptError>
///
pub fn decode(script: &[u8]) -> Result<Vec<ScriptToken>, ScriptError> {
    let mut instructions: Vec<ScriptToken> = Vec::new(); // 待定指令集
    let mut pc = 0; // 当前指针

    while pc < script.len() {
        let byte = read_byte(script, &mut pc)?;

        match byte {
            // Direct Push
            // 0x01..=0x4b 本身不是具名 opcode，而是后续数据长度。最大75字节。
            // 参考v0.3.19 script.h 533行  if (opcode < OP_PUSHDATA1)
            b if (0x01..=0x4b).contains(&b) => {
                let bytes = read_bytes(script, &mut pc, to_usize(b)?)?;
                instructions.push(ScriptToken::Data {
                    kind: PushDataKind::Direct(b),
                    bytes,
                });
            }

            // PushData1
            // PushData1 后面 1 字节表示数据长度
            b if b == PushOp::PushData1.byte() => {
                let delta = read_byte(script, &mut pc)?;
                let bytes = read_bytes(script, &mut pc, to_usize(delta)?)?;
                instructions.push(ScriptToken::Data {
                    kind: PushDataKind::PushData1,
                    bytes,
                });
            }
            // PushData2
            // PushData2 后面 2 字节小端整数表示数据长度
            b if b == PushOp::PushData2.byte() => {
                let delta_bytes = read_bytes(script, &mut pc, 2)?;
                let delta = u16::from_le_bytes([delta_bytes[0], delta_bytes[1]]);
                let bytes = read_bytes(script, &mut pc, to_usize(delta)?)?;
                instructions.push(ScriptToken::Data {
                    kind: PushDataKind::PushData2,
                    bytes,
                });
            }
            // PushData4
            // PushData4 后面 4 字节小端整数表示数据长度
            b if b == PushOp::PushData4.byte() => {
                let delta_bytes = read_bytes(script, &mut pc, 4)?;
                let delta = u32::from_le_bytes([
                    delta_bytes[0],
                    delta_bytes[1],
                    delta_bytes[2],
                    delta_bytes[3],
                ]);
                let bytes = read_bytes(script, &mut pc, to_usize(delta)?)?;
                instructions.push(ScriptToken::Data {
                    kind: PushDataKind::PushData4,
                    bytes,
                });
            }
            // OpCode
            b => {
                let op_code = OpCode::from_byte(b).ok_or(ScriptError::InvalidOpcode(b))?;
                instructions.push(ScriptToken::Command(op_code))
            }
        }
    }
    Ok(instructions)
}

///
/// 编码： 结构化数据 => 字节流
/// # Arguments
///
/// * `instructions`: 指令集
///
/// returns: Result<Vec<u8>, ScriptError> 字节流
///
pub fn encode(instructions: &[ScriptToken]) -> Result<Vec<u8>, ScriptError> {
    let mut script = Vec::new();

    for instruction in instructions {
        match instruction {
            // 具名操作码
            ScriptToken::Command(opcode) => {
                script.push(opcode.byte());
            }
            // 压栈数据
            ScriptToken::Data { kind, bytes } => {
                match kind {
                    // 直接压栈数据
                    PushDataKind::Direct(n) => {
                        // 检查 n 范围和 bytes.len()
                        // 写入 n
                        // 写入 bytes
                        if !(0x01..=0x4b).contains(n) {
                            return Err(ScriptError::InvalidPushDataDirect { actual: *n });
                        }

                        let expected_len = to_usize(*n)?;
                        let len = bytes.len();

                        if len != expected_len {
                            return Err(ScriptError::PushDataLengthMismatch {
                                kind: "Direct",
                                expected: expected_len,
                                actual: len,
                            });
                        }
                        script.push(*n);
                        script.extend_from_slice(bytes);
                    }
                    // PushData1
                    PushDataKind::PushData1 => {
                        // 检查 bytes.len() <= u8::MAX
                        // 写入 OP_PUSHDATA1
                        // 写入 1 字节长度
                        // 写入 bytes
                        let max = to_usize(u8::MAX)?;
                        let len = bytes.len();

                        if len > max {
                            return Err(ScriptError::PushDataLengthTooLarge {
                                kind: "PushData1",
                                max,
                                actual: len,
                            });
                        }
                        script.push(PushOp::PushData1.byte());
                        script.push(len as u8);
                        script.extend_from_slice(bytes);
                    }

                    //PushData2
                    PushDataKind::PushData2 => {
                        // 检查 bytes.len() <= u16::MAX
                        // 写入 OP_PUSHDATA2
                        // 写入 2 字节小端长度
                        // 写入 bytes
                        let max = to_usize(u16::MAX)?;
                        let len = bytes.len();

                        if len > max {
                            return Err(ScriptError::PushDataLengthTooLarge {
                                kind: "PushData2",
                                max,
                                actual: len,
                            });
                        }
                        script.push(PushOp::PushData2.byte());
                        let n: [u8; 2] = (len as u16).to_le_bytes();
                        script.extend_from_slice(&n);
                        script.extend_from_slice(bytes);
                    }
                    //PushData4
                    PushDataKind::PushData4 => {
                        // 检查 bytes.len() <= u32::MAX
                        // 写入 OP_PUSHDATA4
                        // 写入 4 字节小端长度
                        // 写入 bytes

                        let max = to_usize(u32::MAX)?;
                        let len = bytes.len();
                        if len > max {
                            return Err(ScriptError::PushDataLengthTooLarge {
                                kind: "PushData4",
                                max,
                                actual: len,
                            });
                        }
                        script.push(PushOp::PushData4.byte());
                        let n: [u8; 4] = (len as u32).to_le_bytes();
                        script.extend_from_slice(&n);
                        script.extend_from_slice(bytes);
                    }
                }
            }
        }
    }
    Ok(script)
}

///
/// 根据当前指针和指针增量(delta),读取多个字节(n*u8)
/// ## Arguments
///
/// * `script`: 脚本字节流，不可变引用
/// * `pc`: 可变引用，当前指针位置
/// * `delta`: 指针增量
///
/// returns: Result<Vec<u8>, ScriptError>
///
fn read_bytes(script: &[u8], pc: &mut usize, delta: usize) -> Result<Vec<u8>, ScriptError> {
    // let end = pc.add(delta);
    let end = pc
        .checked_add(delta)
        .ok_or(ScriptError::UnexpectedEndOfScript)?;
    if end > script.len() {
        // 脚本声明后面有 N 字节，但实际没有这么多字节
        return Err(ScriptError::UnexpectedEndOfScript);
    }
    let bytes = script[*pc..end].to_vec();
    *pc = end;
    Ok(bytes)
}

///
/// 根据当前指针读取一个字节(u8)
/// # Arguments
///
/// * `script`: 脚本字节流
/// * `pc`: 当前指针位置，可变引用
///
/// returns: Result<u8, ScriptError>
///
fn read_byte(script: &[u8], pc: &mut usize) -> Result<u8, ScriptError> {
    let byte = *script.get(*pc).ok_or(ScriptError::UnexpectedEndOfScript)?;
    *pc += 1;
    Ok(byte)
}

///
/// 类型转化 u8/u16/u32=> usize
/// # Arguments
///
/// * `value`:
///
/// returns: Result<usize, ScriptError>
///
fn to_usize<T>(value: T) -> Result<usize, ScriptError>
where
    T: TryInto<usize>,
    T::Error: ToString,
{
    value
        .try_into()
        .map_err(|e| ScriptError::OtherError(e.to_string()))
}
