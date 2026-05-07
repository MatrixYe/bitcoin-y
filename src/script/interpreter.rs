use crate::script::consts::{MAX_OPS_PER_SCRIPT, MAX_SCRIPT_ELEMENT_SIZE, MAX_STACK_SIZE};
use crate::script::opcode::{
    BitLogicOp, ControlOp, CryptoOp, ExpansionOp, NumericOp, OpCode, PushOp, SpliceOp, StackOp,
};
use crate::script::parser::ScriptToken;
use crate::script::ScriptError;

pub type Stack = Vec<Vec<u8>>;

#[derive(Debug, Clone, Default)]
pub struct Interpreter {
    pub stack: Stack,      // 主栈
    alt_stack: Stack,      // 备用栈
    exec_stack: Vec<bool>, // 条件执行栈，后续实现 OP_IF / OP_ELSE / OP_ENDIF 时使用
    op_count: usize,       // 非 push 操作码计数
}

impl Interpreter {
    // 构造
    pub fn new() -> Self {
        Self::default()
    }
    // 使用已有主栈构造
    // 用于执行 scriptSig 后继续执行 scriptPubKey。
    pub fn with_stack(stack: Stack) -> Self {
        Self {
            stack,
            ..Self::default()
        }
    }
    // 入栈
    fn push(&mut self, value: Vec<u8>) -> Result<(), ScriptError> {
        let le = value.len();
        if le > MAX_SCRIPT_ELEMENT_SIZE {
            //每次入栈的字节大小最多为 MAX_SCRIPT_ELEMENT_SIZE=520
            return Err(ScriptError::ElementTooLarge {
                max: MAX_SCRIPT_ELEMENT_SIZE,
                actual: le,
            });
        }
        self.stack.push(value);
        Ok(())
    }
    // 出栈
    fn pop(&mut self) -> Result<Vec<u8>, ScriptError> {
        self.stack.pop().ok_or(ScriptError::StackUnderflow)
    }

    // 检测栈(主栈+备用栈)的元素数量
    fn check_stack_size(&self) -> Result<(), ScriptError> {
        if self.stack.len() + self.alt_stack.len() > MAX_STACK_SIZE {
            // 主栈 + 备用栈的元素数量最多为 MAX_STACK_SIZE= 1_000;
            return Err(ScriptError::StackOverflow);
        }
        Ok(())
    }
    // 统计opcode数量
    fn count_op(&mut self, code: OpCode) -> Result<(), ScriptError> {
        if code.byte() > PushOp::Op16.byte() {
            self.op_count += 1;
            if self.op_count > MAX_OPS_PER_SCRIPT {
                return Err(ScriptError::TooManyOps);
            }
        }
        Ok(())
    }
    /*
        execute -> execute_opcode -> exec_xxx_op
                -> push data
    */
    pub fn execute(&mut self, instructions: &[ScriptToken]) -> Result<(), ScriptError> {
        for instruction in instructions {
            match instruction {
                // 操作码入栈
                ScriptToken::Command(opcode) => {
                    self.count_op(*opcode)?;
                    self.execute_opcode(*opcode)?;
                }
                // 数据直接入栈
                ScriptToken::Data(data) => {
                    self.push(data.stack_bytes()?)?;
                }
            }
            self.check_stack_size()?;
        }
        Ok(())
    }
    fn execute_opcode(&mut self, op_code: OpCode) -> Result<(), ScriptError> {
        match op_code {
            OpCode::Push(op) => self.execute_push_op(op)?,
            OpCode::Control(op) => self.exec_control_op(op)?,
            OpCode::Stack(op) => self.exec_stack_op(op)?,
            OpCode::Splice(op) => self.exec_splice_op(op)?,
            OpCode::BitLogic(op) => self.exec_bit_logic_op(op)?,
            OpCode::Numeric(op) => self.exec_numeric_op(op)?,
            OpCode::Crypto(op) => self.exec_crypto_op(op)?,
            OpCode::Expansion(op) => self.exec_expansion_op(op)?,
            OpCode::Invalid(op) => return Err(ScriptError::InvalidOpcode(op.byte())),
        }
        Ok(())
    }

    fn execute_push_op(&mut self, op: PushOp) -> Result<(), ScriptError> {
        match op {
            PushOp::OpReserved => { Err(ScriptError::ReservedOpcode(op.byte())) }
            _ => {
                /*
                parser 已经把 PUSHDATA1/2/4 解析成 ScriptToken::Data，
                parser 已经把 Op0~OP16,以及Op1Negate 解析成 ScriptToken::Data，
                执行器不应该再看到它们作为 OpCode::Push(PushOp::PushData1/2/4)进入 execute_push_op。
                如果后续真的遇到，说明绕过了正常路径，或者有人手动构造了不规范的Instruction::Command(OpCode::Push(PushOp::PushData1))。
                应该返回UnsupportedScriptForm
                */
                Err(ScriptError::UnsupportedScriptForm)
            }
        }
    }

    fn exec_control_op(&mut self, op: ControlOp) -> Result<(), ScriptError> {
        match op {
            ControlOp::Nop => {}
            ControlOp::Ver => {}
            ControlOp::If => {}
            ControlOp::NotIf => {}
            ControlOp::VerIf => {}
            ControlOp::VerNotIf => {}
            ControlOp::Else => {}
            ControlOp::EndIf => {}
            ControlOp::Verify => {}
            ControlOp::Return => {}
        }
        Ok(())
    }

    fn exec_stack_op(&mut self, op: StackOp) -> Result<(), ScriptError> {
        match op {
            StackOp::ToAltStack => {}
            StackOp::FromAltStack => {}
            StackOp::Op2Drop => {}
            StackOp::Op2Dup => {}
            StackOp::Op3Dup => {}
            StackOp::Op2Over => {}
            StackOp::Op2Rot => {}
            StackOp::Op2Swap => {}
            StackOp::IfDup => {}
            StackOp::Depth => {}
            StackOp::Drop => {}
            StackOp::Dup => {}
            StackOp::Nip => {}
            StackOp::Over => {}
            StackOp::Pick => {}
            StackOp::Roll => {}
            StackOp::Rot => {}
            StackOp::Swap => {}
            StackOp::Tuck => {}
        }
        Ok(())
    }

    fn exec_splice_op(&mut self, op: SpliceOp) -> Result<(), ScriptError> {
        match op {
            SpliceOp::Cat => {}
            SpliceOp::SubStr => {}
            SpliceOp::Left => {}
            SpliceOp::Right => {}
            SpliceOp::Size => {}
        }
        Ok(())
    }

    fn exec_bit_logic_op(&mut self, op: BitLogicOp) -> Result<(), ScriptError> {
        match op {
            BitLogicOp::Invert => {}
            BitLogicOp::And => {}
            BitLogicOp::Or => {}
            BitLogicOp::Xor => {}
            BitLogicOp::Equal => {}
            BitLogicOp::EqualVerify => {}
            BitLogicOp::Reserved1 => {}
            BitLogicOp::Reserved2 => {}
        }
        Ok(())
    }

    fn exec_numeric_op(&mut self, op: NumericOp) -> Result<(), ScriptError> {
        match op {
            NumericOp::Op1Add => {}
            NumericOp::Op1Sub => {}
            NumericOp::Op2Mul => {}
            NumericOp::Op2Div => {}
            NumericOp::Negate => {}
            NumericOp::Abs => {}
            NumericOp::Not => {}
            NumericOp::Op0NotEqual => {}
            NumericOp::Add => {}
            NumericOp::Sub => {}
            NumericOp::Mul => {}
            NumericOp::Div => {}
            NumericOp::Mod => {}
            NumericOp::LShift => {}
            NumericOp::RShift => {}
            NumericOp::BoolAnd => {}
            NumericOp::BoolOr => {}
            NumericOp::NumEqual => {}
            NumericOp::NumEqualVerify => {}
            NumericOp::NumNotEqual => {}
            NumericOp::LessThan => {}
            NumericOp::GreaterThan => {}
            NumericOp::LessThanOrEqual => {}
            NumericOp::GreaterThanOrEqual => {}
            NumericOp::Min => {}
            NumericOp::Max => {}
            NumericOp::Within => {}
        }
        Ok(())
    }

    fn exec_crypto_op(&mut self, op: CryptoOp) -> Result<(), ScriptError> {
        match op {
            CryptoOp::Ripemd160 => {}
            CryptoOp::Sha1 => {}
            CryptoOp::Sha256 => {}
            CryptoOp::Hash160 => {}
            CryptoOp::Hash256 => {}
            CryptoOp::CodeSeparator => {}
            CryptoOp::CheckSig => {}
            CryptoOp::CheckSigVerify => {}
            CryptoOp::CheckMultiSig => {}
            CryptoOp::CheckMultiSigVerify => {}
        }
        Ok(())
    }

    fn exec_expansion_op(&mut self, op: ExpansionOp) -> Result<(), ScriptError> {
        match op {
            ExpansionOp::Nop1 => {}
            ExpansionOp::Nop2 => {}
            ExpansionOp::Nop3 => {}
            ExpansionOp::Nop4 => {}
            ExpansionOp::Nop5 => {}
            ExpansionOp::Nop6 => {}
            ExpansionOp::Nop7 => {}
            ExpansionOp::Nop8 => {}
            ExpansionOp::Nop9 => {}
            ExpansionOp::Nop10 => {}
            ExpansionOp::CheckSigAdd => {}
        }
        Ok(())
    }
}
