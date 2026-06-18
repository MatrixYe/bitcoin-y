use crate::bignum::BigNum;
use crate::script::consts::MAX_SCRIPT_SIZE;
use crate::script::opcode::{OpCode, PushValue};
use crate::script::{Script, ScriptError};

/// @Name: builder
///
/// @Date: 2026/6/11 16:50
///
/// @Author: Matrix.Ye
///
/// @Description: 脚本构造器
/// Push 编码规则
///
/// ```text
/// 长度 0              -> OP_0
/// 长度 1..=75         -> `[长度字节]` + data
/// 长度 76..=255       -> OP_PUSHDATA1 + u8长度 + data
/// 长度 256..=65535    -> OP_PUSHDATA2 + u16小端长度 + data
/// 更长                -> OP_PUSHDATA4 + u32小端长度 + data
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScriptBuilder {
    data: Script,
}

impl ScriptBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// 使用能够表达数据长度的最短 push 编码写入字节串
    pub fn push_bytes(&mut self, bytes: &[u8]) -> Result<&mut Self, ScriptError> {
        let prefix_len = match bytes.len() {
            0 | 1..=0x4b => 1,
            0x4c..=0xff => 2,
            0x100..=0xffff => 3,
            _ => 5,
        };
        self.ensure_can_append(prefix_len, bytes.len())?;

        match bytes.len() {
            0 => self.data.push(PushValue::Op0.byte()),
            len @ 1..=0x4b => self.data.push(len as u8),
            len @ 0x4c..=0xff => {
                self.data.push(PushValue::PushData1.byte());
                self.data.push(len as u8);
            }
            len @ 0x100..=0xffff => {
                self.data.push(PushValue::PushData2.byte());
                self.data.extend_from_slice(&(len as u16).to_le_bytes());
            }
            len => {
                let len = u32::try_from(len).map_err(|_| ScriptError::PushDataLengthTooLarge {
                    kind: "OP_PUSHDATA4",
                    max: u32::MAX as usize,
                    actual: len,
                })?;
                self.data.push(PushValue::PushData4.byte());
                self.data.extend_from_slice(&len.to_le_bytes());
            }
        }

        self.data.extend_from_slice(bytes);
        Ok(self)
    }

    /// 将 UTF-8 字符串作为普通脚本数据写入
    pub fn push_str(&mut self, string: &str) -> Result<&mut Self, ScriptError> {
        self.push_bytes(string.as_bytes())
    }

    /// 使用 Bitcoin ScriptNum 的符号-绝对值格式写入大整数
    pub fn push_script_num(&mut self, num: &BigNum) -> Result<&mut Self, ScriptError> {
        self.push_bytes(&num.to_bytes_le())
    }

    /// 写入一个已经由类型系统验证的操作码
    pub fn push_opcode(&mut self, opcode: OpCode) -> Result<&mut Self, ScriptError> {
        self.ensure_can_append(1, 0)?;
        self.data.push(opcode.byte());
        Ok(self)
    }

    /// 完成构造并移交脚本所有权
    pub fn into_script(self) -> Result<Script, ScriptError> {
        Ok(self.data)
    }

    fn ensure_can_append(&self, prefix_len: usize, data_len: usize) -> Result<(), ScriptError> {
        let actual = self
            .data
            .len()
            .checked_add(prefix_len)
            .and_then(|len| len.checked_add(data_len))
            .unwrap_or(usize::MAX);

        // 最大10_000
        if actual > MAX_SCRIPT_SIZE {
            Err(ScriptError::ScriptTooLarge {
                max: MAX_SCRIPT_SIZE,
                actual,
            })
        } else {
            Ok(())
        }
    }
}
