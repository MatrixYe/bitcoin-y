use crate::script::ScriptError;
use crate::script::opcode::{OpCode, PushOp};

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
pub enum Instruction {
    //表示一个具名 opcode，比如 OP_DUP、OP_1、OP_CHECKSIG。
    Op(OpCode),

    //表示 parser 已经从脚本字节流里取出一段 payload bytes，执行器只需要把它压栈。
    PushBytes { kind: PushBytesKind, data: Vec<u8> },
}

// 数据压栈方式
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushBytesKind {
    Direct(u8), // 直接压栈，
    PushData1,  // 下1个字节表示即将压栈的数据长度，最大u8::MAX
    PushData2,  // 下2个字节表示即将压栈的数据长度，最大u16::MAX
    PushData4,  // 下4个字节表示即将压栈的数据长度，最大u32::MAX
}

impl fmt::Display for PushBytesKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct(n) => write!(f, "Direct({n})"),
            Self::PushData1 => f.write_str("OP_PUSHDATA1"),
            Self::PushData2 => f.write_str("OP_PUSHDATA2"),
            Self::PushData4 => f.write_str("OP_PUSHDATA4"),
        }
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Op(opcode) => write!(f, "{opcode}"),
            Self::PushBytes { kind, data } => {
                write!(f, "{kind} len={} data=0x{}", data.len(), hex::encode(data))
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
/// returns: Result<Vec<Instruction>, ScriptError>
///
pub fn decode(script: &[u8]) -> Result<Vec<Instruction>, ScriptError> {
    let mut instructions: Vec<Instruction> = Vec::new(); // 待定指令集
    let mut pc = 0; // 当前指针

    while pc < script.len() {
        let byte = read_byte(script, &mut pc)?;

        match byte {
            // Direct Push
            // 0x01..=0x4b 本身不是具名 opcode，而是后续数据长度。
            // 参考v0.3.19 script.h 533行  if (opcode < OP_PUSHDATA1)
            b if (0x01..=0x4b).contains(&b) => {
                let data = read_bytes(script, &mut pc, to_usize(b)?)?;
                instructions.push(Instruction::PushBytes {
                    kind: PushBytesKind::Direct(b),
                    data,
                });
            }

            // PushData1
            // PushData1 后面 1 字节表示数据长度
            b if b == PushOp::PushData1.byte() => {
                let delta = read_byte(script, &mut pc)?;
                let data = read_bytes(script, &mut pc, to_usize(delta)?)?;
                instructions.push(Instruction::PushBytes {
                    kind: PushBytesKind::PushData1,
                    data,
                });
            }
            // PushData2
            // PushData2 后面 2 字节小端整数表示数据长度
            b if b == PushOp::PushData2.byte() => {
                let delta_bytes = read_bytes(script, &mut pc, 2)?;
                let delta = u16::from_le_bytes([delta_bytes[0], delta_bytes[1]]);
                let data = read_bytes(script, &mut pc, to_usize(delta)?)?;
                instructions.push(Instruction::PushBytes {
                    kind: PushBytesKind::PushData2,
                    data,
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
                let data = read_bytes(script, &mut pc, to_usize(delta)?)?;
                instructions.push(Instruction::PushBytes {
                    kind: PushBytesKind::PushData4,
                    data,
                });
            }
            // OpCode
            b => {
                let op_code = OpCode::from_byte(b).ok_or(ScriptError::InvalidOpcode(b))?;
                instructions.push(Instruction::Op(op_code))
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
pub fn encode(instructions: &[Instruction]) -> Result<Vec<u8>, ScriptError> {
    let mut script = Vec::new();

    for instruction in instructions {
        match instruction {
            // 具名操作码
            Instruction::Op(opcode) => {
                script.push(opcode.byte());
            }
            // 压栈数据
            Instruction::PushBytes { kind, data } => {
                match kind {
                    // 直接压栈数据
                    PushBytesKind::Direct(n) => {
                        // 检查 n 范围和 data.len()
                        // 写入 n
                        // 写入 data
                        if !(0x01..=0x4b).contains(n) {
                            return Err(ScriptError::InvalidPushDataDirect { actual: *n });
                        }

                        let expected_len = to_usize(*n)?;
                        let len = data.len();

                        if len != expected_len {
                            return Err(ScriptError::PushDataLengthMismatch {
                                kind: "Direct",
                                expected: expected_len,
                                actual: len,
                            });
                        }
                        script.push(*n);
                        script.extend_from_slice(data);
                    }
                    // PushData1
                    PushBytesKind::PushData1 => {
                        // 检查 data.len() <= u8::MAX
                        // 写入 OP_PUSHDATA1
                        // 写入 1 字节长度
                        // 写入 data
                        let max = to_usize(u8::MAX)?;
                        let len = data.len();

                        if len > max {
                            return Err(ScriptError::PushDataLengthTooLarge {
                                kind: "PushData1",
                                max,
                                actual: len,
                            });
                        }
                        script.push(PushOp::PushData1.byte());
                        script.push(len as u8);
                        script.extend_from_slice(data);
                    }

                    //PushData2
                    PushBytesKind::PushData2 => {
                        // 检查 data.len() <= u16::MAX
                        // 写入 OP_PUSHDATA2
                        // 写入 2 字节小端长度
                        // 写入 data
                        let max = to_usize(u16::MAX)?;
                        let len = data.len();

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
                        script.extend_from_slice(data);
                    }
                    //PushData4
                    PushBytesKind::PushData4 => {
                        // 检查 data.len() <= u32::MAX
                        // 写入 OP_PUSHDATA4
                        // 写入 4 字节小端长度
                        // 写入 data

                        let max = to_usize(u32::MAX)?;
                        let len = data.len();
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
                        script.extend_from_slice(data);
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
    let data = script[*pc..end].to_vec();
    *pc = end;
    Ok(data)
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
