use crate::script::consts::{MAX_OPS_PER_SCRIPT, MAX_SCRIPT_ELEMENT_SIZE, MAX_SCRIPT_NUM_SIZE, MAX_STACK_SIZE};
use crate::script::opcode::{
    BitLogicOp, ControlOp, CryptoOp, ExpansionOp, NumericOp, OpCode, PushOp, SpliceOp, StackOp,
};
use crate::script::parser::ScriptToken;
use crate::script::ScriptError;


pub type Stack = Vec<Vec<u8>>;

#[derive(Debug, Clone, Default)]
pub struct Interpreter {
    // 主栈
    pub stack: Stack,
    // 备用栈,提供一个临时存放区只通过 OP_TOALTSTACK / OP_FROMALTSTACK 显式移动数据。

    alt_stack: Stack,

    // 条件执行栈（非数据栈） OP_IF / OP_ELSE / OP_ENDIF 时使用
    vf_exec: Vec<bool>,

    // 非 push 操作码计数
    op_count: usize,
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
    // 弹出 主栈
    fn pop(&mut self) -> Result<Vec<u8>, ScriptError> {
        self.stack.pop().ok_or(ScriptError::StackUnderflow)
    }

    // 弹出备用栈出栈
    fn pop_alt(&mut self) -> Result<Vec<u8>, ScriptError> {
        self.alt_stack.pop().ok_or(ScriptError::StackUnderflow)
    }

    // 获取主栈长度
    fn stack_len(&self) -> usize {
        self.stack.len()
    }

    fn require_stack(&self, len: usize) -> Result<(), ScriptError> {
        if self.stack_len() < len {
            return Err(ScriptError::StackUnderflow);
        }
        Ok(())
    }

    // 检测栈(主栈+备用栈)的元素数量
    fn check_stack_size(&self) -> Result<(), ScriptError> {
        if self.stack_len() + self.alt_stack.len() > MAX_STACK_SIZE {
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

                // 数据直接入栈
                ScriptToken::Data(data) => {
                    self.push(data.stack_bytes()?)?;
                }
                // 操作码入栈
                ScriptToken::Command(opcode) => {
                    self.count_op(*opcode)?;
                    self.execute_opcode(*opcode)?;
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
            PushOp::OpReserved => {
                Err(ScriptError::ReservedOpcode(op.byte()))
            }
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


    /// OP_TOALTSTACK: 移动到备用栈,要求主栈至少 1 个元素,原版逻辑是把主栈顶复制到 altstack，然后从主栈弹出。`主栈:   [x] -> [] ;备用栈: []  -> [x]`
    ///
    /// OP_FROMALTSTACK: 要求备用栈至少 1 个元素,原版逻辑是把备用栈顶移动回主栈。
    ///
    /// OP_DROP: 删除主栈顶 1 个元素,要求至少 1 个元素。`[x] -> []`
    ///
    /// OP_2DROP: 删除主栈顶 2 个元素,要求至少 2 个元素。`[x1, x2] -> []`
    ///
    /// OP_NIP: 删除栈顶下面的那个元素，保留栈顶。要求至少 2 个元素。原版用 `stack.erase(stack.end() - 2);`
    ///
    /// OP_DUP: 复制栈顶,要求至少 1 个元素。 `[x] -> [x, x]`
    ///
    /// OP_2DUP: 复制栈顶两个元素,要求至少 2 个元素。`[x1, x2] -> [x1, x2, x1, x2]`
    ///
    /// OP_3DUP: 复制栈顶三个元素,要求至少 3 个元素。`[x1, x2, x3] -> [x1, x2, x3, x1, x2, x3]`
    ///
    /// OP_OVER: 复制“栈顶下面的元素”到栈顶,要求至少 2 个元素。`[x1, x2] -> [x1, x2, x1]`
    ///
    /// OP_2OVER: 复制更深处的两个元素到栈顶,要求至少 4 个元素。`[x1, x2, x3, x4] -> [x1, x2, x3, x4, x1, x2]`
    ///
    /// OP_IFDUP: 复制更深处的两个元素到栈顶,要求至少 4 个元素。`[x] -> [x, x] | [x]`  如果 x 为 true
    ///
    /// OP_SWAP: 交换栈顶两个元素,要求至少 2 个元素。`[x1, x2] -> [x2, x1]`
    ///
    /// OP_2SWAP: 交换栈顶两组双元素,要求至少 4 个元素。`[x1, x2, x3, x4] -> [x3, x4, x1, x2]`
    ///
    /// OP_ROT: 把第三个元素旋转到栈顶,要求至少 3 个元素,原版用两次 swap 实现。`[x1, x2, x3] -> [x2, x3, x1]`
    ///
    /// OP_2ROT: 把最深的一组两个元素移动到栈顶。要求至少 6 个元素。原版先取 x1 x2，从原位置删除，再追加到末尾。`[x1, x2, x3, x4, x5, x6] -> [x3, x4, x5, x6, x1, x2]`
    ///
    /// OP_TUCK: 复制栈顶元素，并插入到两个元素下面。要求至少 2 个元素。`[x1, x2] -> [x2, x1, x2]`
    ///
    /// OP_DEPTH: 把当前主栈元素数量压栈。原版用 `CBigNum(stack.size()).getvch()`。`[] -> [0] ; [x1, x2]  -> [x1, x2, 2]`
    ///
    /// OP_PICK: 先从栈顶取出数字 n，然后复制距离栈顶第 n 个元素到栈顶。n = 0 表示复制原来的栈顶元素。要求至少 2 个元素，且 n >= 0 && n < stack.len()。`[xn, ..., x2, x1, x0, n] -> [xn, ..., x2, x1, x0, xn]`
    ///
    /// OP_ROLL: 和 OP_PICK 类似，但不是复制，而是把那个元素移动到栈顶。原版在取出目标元素后，如果是 OP_ROLL，会从原位置删除它。`[xn, ..., x2, x1, x0, n] -> [..., x2, x1, x0, xn]`
    ///
    fn exec_stack_op(&mut self, op: StackOp) -> Result<(), ScriptError> {
        // 19个opcode
        match op {
            // 将主栈栈顶移动到备用栈 `主栈:[x] -> [] ;备用栈:[]  -> [x]`
            StackOp::ToAltStack => {
                let value = self.pop()?;
                self.alt_stack.push(value);
            }

            //将备用栈栈顶移动到主栈
            StackOp::FromAltStack => {
                let value = self.pop_alt()?;
                self.push(value)?;
            }

            //复制主栈栈顶 `[x] -> [x, x]`
            StackOp::Dup => {
                self.require_stack(1)?;
                let len = self.stack_len();
                let last = self.stack[len - 1].clone();
                self.stack.push(last);
            }

            //栈顶为真时复制栈顶
            StackOp::IfDup => {
                self.require_stack(1)?;
                let len = self.stack_len();
                let value = self.stack[len - 1].clone();
                if cast_to_bool(&value) {
                    self.push(value)?;
                }
            }

            //复制主栈顶两个元素
            //`[x1, x2] -> [x1, x2, x1, x2]`
            StackOp::Op2Dup => {
                self.require_stack(2)?;
                let len = self.stack_len();
                self.stack.extend_from_within(len - 2..len);
            }

            //复制主栈顶三个元素
            //`[x1, x2, x3] -> [x1, x2, x3, x1, x2, x3]`
            StackOp::Op3Dup => {
                self.require_stack(3)?;
                let len = self.stack_len();
                self.stack.extend_from_within(len - 3..len);
            }


            //复制“栈顶下面的元素”到栈顶,要求至少 2 个元素。
            // `[x1, x2] -> [x1, x2, x1]`
            StackOp::Over => {
                self.require_stack(2)?;
                let len = self.stack_len();
                self.stack.push(self.stack[len - 2].clone());
            }

            //复制主栈中指定的两个较深元素到栈顶
            //`[x1, x2, x3, x4] -> [x1, x2, x3, x4, x1, x2]`
            StackOp::Op2Over => {
                self.require_stack(4)?;
                let len = self.stack_len();
                self.stack.extend_from_within(len - 4..len - 2);
            }


            // OP_TUCK: 复制栈顶元素，并插入到两个元素下面。
            // 要求至少 2 个元素。
            // `[x1, x2] -> [x2, x1, x2]`
            StackOp::Tuck => {
                self.require_stack(2)?;
                let len = self.stack_len();
                let v = self.stack[len - 1].clone();
                self.stack.insert(len - 2, v);
            }

            //删除主栈顶 1 个元素,要求至少 1 个元素。`[x] -> []`
            StackOp::Drop => {
                self.pop()?;
            }
            //丢弃主栈顶两个元素
            //`[x1, x2] -> []`
            StackOp::Op2Drop => {
                self.require_stack(2)?;
                self.pop()?;
                self.pop()?;
            }

            //删除栈顶下方的一个元素
            //[x1, x2] -> [x2]
            StackOp::Nip => {
                self.require_stack(2)?;
                let len = self.stack_len();
                self.stack.remove(len - 2);
            }


            // 交换主栈顶两个元素
            // [x1,x2,x3] => [x1,x3,x2]
            StackOp::Swap => {
                self.require_stack(2)?;
                let len = self.stack_len();
                self.stack.swap(len - 2, len - 1);
            }
            //交换主栈顶两组双元素
            // [x0,x1,x2,x3] => [x2,x3,x0,x1]
            StackOp::Op2Swap => {
                self.require_stack(4)?;
                let len = self.stack_len();
                self.stack.swap(len - 4, len - 2); //0,2
                self.stack.swap(len - 3, len - 1); //1,3
            }
            // 旋转主栈顶三个元素
            // [x0,x1,x2] => [x1,x0,x2] => [x1,x2,x0]
            StackOp::Rot => {
                self.require_stack(3)?;
                let len = self.stack_len();
                self.stack.swap(len - 3, len - 2); //0,1
                self.stack.swap(len - 2, len - 1); // 1,2
            }

            // 把第三组元素旋转到栈顶,要求至少 6 个元素,原版用两次 swap 实现。
            // [x0,x1,x2,x3,x4,x5] => [[x0,x1],[x2,x3],[x4,x5]] => [[x2,x3],[x4,x5],[x0,x1]] => [x2,x3,x4,x5,x0,x1]
            StackOp::Op2Rot => {
                self.require_stack(6)?;
                let len = self.stack_len();
                // 取出栈中较深的2个元素
                let mut values = self.stack.drain(len - 6..=len - 5).collect::<Vec<_>>();
                //移除后重新添加到末尾
                self.stack.append(&mut values);
            }


            // 将当前主栈深度压栈
            StackOp::Depth => {
                let depth = cast_to_script_num(self.stack_len() as i64);
                self.push(depth)?;
            }

            //复制指定深度的元素到栈顶
            //先从栈顶取出数字 n，然后复制距离栈顶第 n 个元素到栈顶。
            // n = 0 表示复制原来的栈顶元素。
            // 要求至少 2 个元素，且 n >= 0 && n < stack.len()。
            // `[xn, ..., x2, x1, x0, n] -> [xn, ..., x2, x1, x0, xn]`
            StackOp::Pick => {
                let index = self.pick_or_roll_index()?;
                let value = self.stack[index].clone();
                self.push(value)?;
            }

            // 移动指定深度的元素到栈顶
            StackOp::Roll => {
                let index = self.pick_or_roll_index()?;
                let value = self.stack.remove(index);
                self.push(value)?;
            }
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

    //-----//
    fn should_execute(&self) -> bool {
        !self.vf_exec.iter().any(|&v| !v)
    }

    // todo 添加注释
    fn pick_or_roll_index(&mut self) -> Result<usize, ScriptError> {
        self.require_stack(2)?;

        let n = cast_to_i64(&self.pop()?)?;
        let len = self.stack_len();
        if n < 0 || n as usize >= len {
            return Err(ScriptError::InvalidStackIndex { index: n, len });
        }

        Ok(len - 1 - n as usize)
    }
}

fn is_conditional_control_op(op: ControlOp) -> bool {
    matches!(op,
        ControlOp::If
        | ControlOp::NotIf
        | ControlOp::Else
        | ControlOp::VerIf
        | ControlOp::VerNotIf
        | ControlOp::EndIf
    )
}

// todo 添加注释
fn cast_to_script_num(value: i64) -> Vec<u8> {
    // 把 Rust 整数转换成 Bitcoin Script 栈中的数字字节。
    // Script 数字使用小端序，最高有效字节的最高位表示符号；0 使用空向量表示。
    if value == 0 {
        return Vec::new();
    }

    let negative = value < 0;
    let mut abs = value.unsigned_abs();
    let mut result = Vec::new();

    while abs > 0 {
        result.push((abs & 0xff) as u8);
        abs >>= 8;
    }

    let last = result.last_mut().expect("non-zero value has at least one byte");
    if *last & 0x80 != 0 {
        result.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        *last |= 0x80;
    }

    result
}

// todo 添加注释
fn cast_to_i64(v: &[u8]) -> Result<i64, ScriptError> {
    // 把 Bitcoin Script 栈中的数字字节解释成 Rust 整数。
    // 参考 v0.3.19 CastToBigNum：普通数值操作最多接受 4 字节。
    if v.len() > MAX_SCRIPT_NUM_SIZE {
        return Err(ScriptError::ScriptNumOverflow {
            max: MAX_SCRIPT_NUM_SIZE,
            actual: v.len(),
        });
    }

    if v.is_empty() {
        return Ok(0);
    }

    let last_index = v.len() - 1;
    let negative = v[last_index] & 0x80 != 0;
    let mut value = 0i64;

    for (index, byte) in v.iter().enumerate() {
        let byte = if index == last_index { *byte & 0x7f } else { *byte };
        value |= i64::from(byte) << (8 * index);
    }

    if negative {
        Ok(-value)
    } else {
        Ok(value)
    }
}

// todo 添加注释
fn cast_to_bool(v: &[u8]) -> bool {
    // Bitcoin Script 的布尔值不是独立类型，而是从栈元素字节解释出来：
    // 空字节、全 0、以及负零（最高有效字节为 0x80 且其余为 0）都为 false。
    // 只要出现非零字节，并且它不是最后一个字节上的负号位，就为 true。
    for (index, byte) in v.iter().enumerate() {
        if *byte == 0 {
            continue;
        }
        return !(index == v.len() - 1 && *byte == 0x80);
    }
    false
}
