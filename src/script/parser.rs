/// @Name: parser
///
/// @Date: 2026/4/24 02:56
///
/// @Author: Matrix.Ye
///
/// @Description: 将字节流转化成指令
///
///
use crate::script::error::ScriptError;

pub struct Instruction {
    pub opcode: u8,
}

impl Instruction {
    pub fn parse(_script: &[u8]) -> Result<Vec<Self>, ScriptError> {
        todo!()
    }
}
