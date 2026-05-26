use crate::script::ScriptError;
use crate::script::opcode::{BitLogic, Numeric, OpCode, Splice};

/// @Name: rule
///
/// @Date: 2026/5/12 16:46
///
/// @Author: Matrix.Ye
///
/// @Description: 脚本操作码禁用规则
///

pub trait ScriptRules {
    fn disabled_opcodes(&self) -> &'static [OpCode];

    fn check_disable(&self, opcode: OpCode) -> Result<(), ScriptError> {
        if self.disabled_opcodes().contains(&opcode) {
            return Err(ScriptError::DisabledOpcode(opcode.byte()));
        }
        Ok(())
    }
}

/// ## 中本聪规则
/// 参考v0.3.19 script.cpp line:101
///
/// ```cpp
///             if (opcode == OP_CAT ||
///                 opcode == OP_SUBSTR ||
///                 opcode == OP_LEFT ||
///                 opcode == OP_RIGHT ||
///                 opcode == OP_INVERT ||
///                 opcode == OP_AND ||
///                 opcode == OP_OR ||
///                 opcode == OP_XOR ||
///                 opcode == OP_2MUL ||
///                 opcode == OP_2DIV ||
///                 opcode == OP_MUL ||
///                 opcode == OP_DIV ||
///                 opcode == OP_MOD ||
///                 opcode == OP_LSHIFT ||
///                 opcode == OP_RSHIFT)
///                 return false;
/// ```
///
const DISABLE_OPCODE_SET_CVE_2010_5137: &[OpCode] = &[
    //
    OpCode::Splice(Splice::OpCat),
    OpCode::Splice(Splice::OpSubStr),
    OpCode::Splice(Splice::OpLeft),
    OpCode::Splice(Splice::OpRight),
    //
    OpCode::BitLogic(BitLogic::OpInvert),
    OpCode::BitLogic(BitLogic::OpAnd),
    OpCode::BitLogic(BitLogic::OpOr),
    OpCode::BitLogic(BitLogic::OpXor),
    //
    OpCode::Numeric(Numeric::Op2Mul),
    OpCode::Numeric(Numeric::Op2Div),
    OpCode::Numeric(Numeric::OpMul),
    OpCode::Numeric(Numeric::OpDiv),
    OpCode::Numeric(Numeric::OpMod),
    //
    OpCode::Numeric(Numeric::OpLShift),
    OpCode::Numeric(Numeric::OpRShift),
];
const DISABLE_OPCODE_SET_OPEN: &[OpCode] = &[];

#[derive(Debug, Clone, Copy, Default)]
pub struct RuleV0_3_19;

#[derive(Debug, Clone, Copy, Default)]
pub struct RuleV1_0_0;

/// 项目实验规则：除保留操作码外，不在规则层禁用任何具备明确语义的操作码。
#[derive(Debug, Clone, Copy, Default)]
pub struct RuleOpen;

impl ScriptRules for RuleV0_3_19 {
    fn disabled_opcodes(&self) -> &'static [OpCode] {
        DISABLE_OPCODE_SET_CVE_2010_5137
    }
}

impl ScriptRules for RuleOpen {
    fn disabled_opcodes(&self) -> &'static [OpCode] {
        DISABLE_OPCODE_SET_OPEN
    }
}

impl ScriptRules for RuleV1_0_0 {
    fn disabled_opcodes(&self) -> &'static [OpCode] {
        DISABLE_OPCODE_SET_CVE_2010_5137
    }
}
