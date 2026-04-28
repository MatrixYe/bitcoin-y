use crate::script::opcode::{OpCode, PushOp};
use crate::script::ScriptError;

/// @Name: parser.rs
///
/// @Date: 2026/4/9 03:41
///
/// @Author: Matrix.Ye
///
/// @Description: 脚本解析器
///

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushBytesKind {
    Direct(u8),
    PushData1,
    PushData2,
    PushData4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instruction {
    //表示一个具名 opcode，比如 OP_DUP、OP_1、OP_CHECKSIG。
    Op(OpCode),

    //表示 parser 已经从脚本字节流里取出一段 payload bytes，执行器只需要把它压栈。
    PushBytes { kind: PushBytesKind, data: Vec<u8> },
}

/// decode: bytes -> structured data
pub fn decode(script: &[u8]) -> Result<Vec<Instruction>, ScriptError> {
    let mut pc = 0;
    let mut instructions = Vec::new();

    while pc < script.len() {
        let byte = read_u8(script, &mut pc)?;

        let instruction = match byte {
            // 0x01..=0x4b 本身不是具名 opcode，而是后续数据长度。
            0x01..=0x4b => {
                let data = read_bytes(script, &mut pc, byte as usize)?;
                Instruction::PushBytes {
                    kind: PushBytesKind::Direct(byte),
                    data,
                }
            }
            byte if byte == PushOp::PushData1.byte() => {
                let len = read_u8(script, &mut pc)? as usize;
                let data = read_bytes(script, &mut pc, len)?;
                Instruction::PushBytes {
                    kind: PushBytesKind::PushData1,
                    data,
                }
            }
            byte if byte == PushOp::PushData2.byte() => {
                let len = read_u16_le(script, &mut pc)? as usize;
                let data = read_bytes(script, &mut pc, len)?;
                Instruction::PushBytes {
                    kind: PushBytesKind::PushData2,
                    data,
                }
            }
            byte if byte == PushOp::PushData4.byte() => {
                let len = read_u32_le(script, &mut pc)? as usize;
                let data = read_bytes(script, &mut pc, len)?;
                Instruction::PushBytes {
                    kind: PushBytesKind::PushData4,
                    data,
                }
            }
            byte => {
                let opcode = OpCode::from_byte(byte).ok_or(ScriptError::InvalidOpcode(byte))?;
                Instruction::Op(opcode)
            }
        };

        instructions.push(instruction);
    }

    Ok(instructions)
}

/// encode: structured data -> bytes
pub fn encode(_instruction: &[Instruction]) -> Result<Vec<u8>, ScriptError> {
    todo!()
}

fn read_u8(script: &[u8], pc: &mut usize) -> Result<u8, ScriptError> {
    let byte = *script.get(*pc).ok_or(ScriptError::UnexpectedEndOfScript)?;
    *pc += 1;
    Ok(byte)
}

fn read_u16_le(script: &[u8], pc: &mut usize) -> Result<u16, ScriptError> {
    let bytes = read_array::<2>(script, pc)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32_le(script: &[u8], pc: &mut usize) -> Result<u32, ScriptError> {
    let bytes = read_array::<4>(script, pc)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_array<const N: usize>(script: &[u8], pc: &mut usize) -> Result<[u8; N], ScriptError> {
    let bytes = read_bytes(script, pc, N)?;
    bytes.try_into().map_err(|_| ScriptError::InvalidPushData)
}

fn read_bytes(script: &[u8], pc: &mut usize, len: usize) -> Result<Vec<u8>, ScriptError> {
    let end = pc.checked_add(len).ok_or(ScriptError::InvalidPushData)?;
    if end > script.len() {
        return Err(ScriptError::UnexpectedEndOfScript);
    }

    let data = script[*pc..end].to_vec();
    *pc = end;
    Ok(data)
}
