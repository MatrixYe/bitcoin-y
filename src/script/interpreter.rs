use crate::bignum::BigNum;
use crate::hash::hash160;
use crate::script::consts::{
    MAX_OPS_PER_SCRIPT, MAX_SCRIPT_ELEMENT_SIZE, MAX_SCRIPT_NUM_SIZE, MAX_STACK_SIZE,
};
use crate::script::opcode::{
    BitLogic, Control, Crypto, Expansion, Numeric, OpCode, PushValue, Splice, Stack,
};
use crate::script::parser::ScriptToken;
use crate::script::rules::{RuleV0_3_19, ScriptRules};
use crate::script::ScriptError;
use std::cmp::max;

/// @Name: interpreter.rs
///
/// @Date: 2026/5/01 01:46
///
/// @Author: Matrix.Ye
///
/// @Description: 比特币脚本核心处理引擎
///

type StackType = Vec<Vec<u8>>; //别名，栈
type ScriptNumType = Vec<u8>; // 别名，栈内数字

/// ## 执行器架构
/// 作为比特币脚本的核心处理引擎，Interpreter的核心是“栈”，作为一种先入后出的数据结构，本项目中用Vec来描述，例如：
/// `[x0,x1,x2,x3]` 其中`x3`的位置即栈顶。根据中本聪设计的栈机结构，本引擎包含了原版定义的主栈、备用栈、和条件栈，以及规则特征。
///
///
/// ## 数据&指令分离
/// Interpreter 引擎的输入对象是 ScriptToken，这个本人定义的数据对象，原版中并没有这个说法。
/// 因为本项目试图用“图灵机”的计算理念重新定义比特币脚本，达到语法上不同，语义上一致的效果。
/// ScriptToken 包含Data或者 Command，二者的处理逻辑不同。对于Data直接压入，对于Command遵循原版逻辑。
/// 如果在Command的处理流程中出现了与Data相关的操作码，那么证明出现了Token的伪造，是攻击行为，Interpreter会避免这种情况发生 UnsupportedScriptForm。
///
///
/// ## 规则约束
/// 与原版(script.cpp line:101)的对操作码的禁用状态处理不同，执行引擎并不会对opcode禁用规则进行定义。
/// 即不会采用手动跳过、返回错误、或者注释逻辑代码的方式来实现操作码禁用。
/// 而是新定义了一个规则范本ScriptRules，由rules模块进行处理，因此在本模块中，并不会出现显式的操作码禁用情况，
/// 默认就是实现了所有操作码的代码逻辑(保留操作码除外)。
/// Interpreter 内部有一个规则对象 rules: R，R 必须实现 ScriptRules trait。
/// 如果调用者不指定 R，默认使用 RuleV0_3_19，规则选择在类型层面明确，运行时不需要 Box<dyn ScriptRules> 这种动态分发
///
///
#[derive(Debug, Clone)]
pub struct Interpreter<R: ScriptRules = RuleV0_3_19> {
    // 主栈
    pub stack: StackType,
    // 备用栈,提供一个临时存放区只通过 OP_TOALSTACK / OP_FROMALSTACK 显式移动数据。
    alt_stack: StackType,

    // 条件执行栈（非数据栈） OP_IF / OP_ELSE / OP_ENDIF 时使用
    vf_exec: Vec<bool>,

    // 非 push 操作码计数
    op_count: usize,

    // 脚本规则：负责判断某个操作码在当前规则版本下是否被禁用。
    rules: R,
}

impl<R> Default for Interpreter<R>
where
    R: ScriptRules + Default,
{
    fn default() -> Self {
        Self {
            stack: StackType::new(),
            alt_stack: StackType::new(),
            vf_exec: Vec::new(),
            op_count: 0,
            rules: R::default(),
        }
    }
}

impl Interpreter<RuleV0_3_19> {
    // 构造，默认规则
    pub fn new() -> Self {
        Self::default()
    }
    // 使用已有主栈构造
    // 用于执行 scriptSig 后继续执行 scriptPubKey。
    pub fn with_stack(stack: StackType) -> Self {
        Self {
            stack,
            ..Self::default()
        }
    }
}

impl<R> Interpreter<R>
where
    R: ScriptRules,
{
    // 使用指定规则构造解释器，用于模拟不同脚本规则版本。
    pub fn with_rules(rules: R) -> Self {
        Self {
            stack: StackType::new(),
            alt_stack: StackType::new(),
            vf_exec: Vec::new(),
            op_count: 0,
            rules,
        }
    }

    // 使用已有主栈和指定规则构造解释器。
    pub fn with_stack_and_rules(stack: StackType, rules: R) -> Self {
        Self {
            stack,
            alt_stack: StackType::new(),
            vf_exec: Vec::new(),
            op_count: 0,
            rules,
        }
    }

    // 入栈：主栈
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
    // 入栈:备用栈
    fn push_alt(&mut self, value: Vec<u8>) -> Result<(), ScriptError> {
        let le = value.len();
        if le > MAX_SCRIPT_ELEMENT_SIZE {
            //每次入栈的字节大小最多为 MAX_SCRIPT_ELEMENT_SIZE=520
            return Err(ScriptError::ElementTooLarge {
                max: MAX_SCRIPT_ELEMENT_SIZE,
                actual: le,
            });
        }
        self.alt_stack.push(value);
        Ok(())
    }

    // 弹出主栈的栈顶元素
    fn pop(&mut self) -> Result<Vec<u8>, ScriptError> {
        self.stack.pop().ok_or(ScriptError::StackUnderflow)
    }
    // 弹出备用栈出栈
    fn pop_alt(&mut self) -> Result<Vec<u8>, ScriptError> {
        self.alt_stack.pop().ok_or(ScriptError::StackUnderflow)
    }

    // 获取栈顶元素,但不弹出
    fn top(&self) -> Result<Vec<u8>, ScriptError> {
        self.top_n(0)
    }

    // 获取栈顶的第n个元素，n=0时表示栈顶
    fn top_n(&self, n: usize) -> Result<Vec<u8>, ScriptError> {
        match self.stack.get(self.top_index(n)?) {
            None => Err(ScriptError::StackUnderflow),
            Some(v) => Ok(v.clone()),
        }
    }

    // 把“从栈顶向下数的深度”转换成 Vec 的真实下标。index=len-(n+1)
    fn top_index(&self, n: usize) -> Result<usize, ScriptError> {
        let offset = n.checked_add(1).ok_or(ScriptError::StackUnderflow)?;
        self.stack_len()
            .checked_sub(offset)
            .ok_or(ScriptError::StackUnderflow)
    }

    // 移除从栈顶向下数的第 n 个元素，n=0 表示移除栈顶。
    fn remove_top_n(&mut self, n: usize) -> Result<Vec<u8>, ScriptError> {
        let index = self.top_index(n)?;
        Ok(self.stack.remove(index))
    }

    // 获取栈底的第n个元素，n=0时表示栈底
    fn bottom_n(&self, n: usize) -> Result<Vec<u8>, ScriptError> {
        match self.stack.get(n) {
            None => Err(ScriptError::StackUnderflow),
            Some(v) => Ok(v.clone()),
        }
    }

    // 获取主栈长度
    fn stack_len(&self) -> usize {
        self.stack.len()
    }

    // 检测当前栈的长度是否符合最小预期
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
        if code.byte() > PushValue::Op16.byte() {
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
                    /*一个非 push opcode 即使随后因为禁用失败，也先被计入 opcode 数量
                    计数限制约束的是脚本结构和执行资源，不是“成功执行过的 opcode 数量
                    */
                    self.count_op(*opcode)?; //计数
                    self.rules.check_disable(*opcode)?; //检查禁用
                    self.execute_opcode(*opcode)?; //执行
                }
            }
            self.check_stack_size()?;
        }
        Ok(())
    }
    fn execute_opcode(&mut self, op_code: OpCode) -> Result<(), ScriptError> {
        match op_code {
            // 完成
            OpCode::Push(op) => self.execute_push_ops(op)?,
            // todo
            OpCode::Control(op) => self.exec_control_ops(op)?,
            // 完成
            OpCode::Stack(op) => self.exec_stack_ops(op)?,
            // 完成
            OpCode::Splice(op) => self.exec_splice_ops(op)?,
            // 完成
            OpCode::BitLogic(op) => self.exec_bit_logic_ops(op)?,
            // 完成
            OpCode::Numeric(op) => self.exec_numeric_ops(op)?,
            // todo
            OpCode::Crypto(op) => self.exec_crypto_ops(op)?,
            // todo
            OpCode::Expansion(op) => self.exec_expansion_ops(op)?,
            // 完成
            OpCode::Invalid(op) => return Err(ScriptError::InvalidOpcode(op.byte())),
        }
        Ok(())
    }

    // ----PushValue-----
    fn execute_push_ops(&mut self, op: PushValue) -> Result<(), ScriptError> {
        match op {
            PushValue::OpReserved => Err(ScriptError::ReservedOpcode(op.byte())),
            _ => {
                /*
                parser 已经把 PUSHDATA1/2/4 解析成 ScriptToken::Data，
                parser 已经把 Op0~OP16,以及Op1Negate 解析成 ScriptToken::Data，
                执行器不应该再看到它们作为 OpCode::Push(PushValue::PushData1/2/4)进入 execute_push_ops。
                如果后续真的遇到，说明绕过了正常路径，或者有人手动构造了不规范的Instruction::Command(OpCode::Push(PushValue::PushData1))。
                应该返回UnsupportedScriptForm
                */
                Err(ScriptError::UnsupportedScriptForm)
            }
        }
    }
    // ----Control-----
    fn exec_control_ops(&mut self, op: Control) -> Result<(), ScriptError> {
        match op {
            Control::OpNop => {}
            Control::OpVer => {}
            Control::OpIf => {}
            Control::OpNotIf => {}
            Control::OpVerIf => {}
            Control::OpVerNotIf => {}
            Control::OpElse => {}
            Control::OpEndIf => {}
            Control::OpVerify => {}
            Control::OpReturn => {}
        }
        Ok(())
    }
    // ----Stack-----
    fn exec_stack_ops(&mut self, op: Stack) -> Result<(), ScriptError> {
        // 19个opcode
        match op {
            // 将主栈栈顶移动到备用栈 `主栈:[x] -> [] ;备用栈:[]  -> [x]`
            Stack::OpToAltStack => {
                let value = self.pop()?;
                self.push_alt(value)?;
            }

            // 将备用栈栈顶移动到主栈
            Stack::OpFromAltStack => {
                let value = self.pop_alt()?;
                self.push(value)?;
            }

            //复制主栈栈顶 `[x] -> [x, x]`
            Stack::OpDup => {
                self.require_stack(1)?;
                self.push(self.top()?)?;
            }

            //栈顶为真时复制栈顶
            Stack::OpIfDup => {
                self.require_stack(1)?;
                let top = self.top()?;
                if cast_script_num_to_bool(&top) {
                    self.push(top)?;
                }
            }

            //复制主栈顶两个元素
            //`[x1, x2] -> [x1, x2, x1, x2]`
            Stack::Op2Dup => {
                self.require_stack(2)?;
                let len = self.stack_len();
                self.stack.extend_from_within(len - 2..len); //根据自身拓展
            }

            //复制主栈顶三个元素
            //`[x1, x2, x3] -> [x1, x2, x3, x1, x2, x3]`
            Stack::Op3Dup => {
                self.require_stack(3)?;
                let len = self.stack_len();
                self.stack.extend_from_within(len - 3..len);
            }

            //复制“栈顶下面的元素”到栈顶,要求至少 2 个元素。
            // `[x1, x2] -> [x1, x2, x1]`
            Stack::OpOver => {
                self.require_stack(2)?;
                self.stack.push(self.top_n(1)?);
            }

            //复制主栈中指定的两个较深元素到栈顶
            //`[x0,x1, x2, x3, x4] -> [x0,x1, x2, x3, x4, x1, x2]`
            Stack::Op2Over => {
                self.require_stack(4)?;
                let len = self.stack_len();
                self.stack.extend_from_within(len - 4..len - 2);
            }

            // OP_TUCK: 复制栈顶元素，并插入到两个元素下面。
            // 要求至少 2 个元素。
            // `[x0,x1, x2] -> [x0,x2, x1, x2]`
            Stack::OpTuck => {
                self.require_stack(2)?;
                let len = self.stack_len();
                let v = self.top()?;
                self.stack.insert(len - 2, v);
            }

            //删除主栈顶 1 个元素,要求至少 1 个元素。`[x] -> []`
            Stack::OpDrop => {
                self.pop()?;
            }
            //丢弃主栈顶两个元素
            //`[x1, x2] -> []`
            Stack::Op2Drop => {
                self.require_stack(2)?;
                self.pop()?;
                self.pop()?;
            }

            //删除栈顶下方的一个元素
            //[x1, x2] -> [x2]
            Stack::OpNip => {
                self.require_stack(2)?;
                self.remove_top_n(1)?;
            }

            // 交换主栈顶两个元素
            // [x1,x2,x3] => [x1,x3,x2]
            Stack::OpSwap => {
                self.require_stack(2)?;
                let len = self.stack_len();
                self.stack.swap(len - 2, len - 1);
            }
            //交换主栈顶两组双元素
            // [x0,x1,x2,x3] => [x2,x3,x0,x1]
            Stack::Op2Swap => {
                self.require_stack(4)?;
                let len = self.stack_len();
                self.stack.swap(len - 4, len - 2); //0,2
                self.stack.swap(len - 3, len - 1); //1,3
            }
            // 旋转主栈顶三个元素
            // [x0,x1,x2] => [x1,x0,x2] => [x1,x2,x0]
            Stack::OpRot => {
                self.require_stack(3)?;
                let len = self.stack_len();
                self.stack.swap(len - 3, len - 2); //0,1
                self.stack.swap(len - 2, len - 1); // 1,2
            }

            // 把第三组元素旋转到栈顶,要求至少 6 个元素,原版用两次 swap 实现。
            // [x0,x1,x2,x3,x4,x5] => [[x0,x1],[x2,x3],[x4,x5]] => [[x2,x3],[x4,x5],[x0,x1]] => [x2,x3,x4,x5,x0,x1]
            Stack::Op2Rot => {
                self.require_stack(6)?;
                let len = self.stack_len();
                // 取出栈中较深的2个元素
                let mut values = self.stack.drain(len - 6..=len - 5).collect::<Vec<_>>();
                //移除后重新添加到末尾
                self.stack.append(&mut values);
            }

            // 将当前主栈深度压栈
            // `[x0,x1,x2,x3] -> [x0,x1,x2,x3,4]`
            Stack::OpDepth => {
                let depth = BigNum::from_usize(self.stack_len());
                self.push_bignum(depth)?;
            }

            // Pick:复制指定深度的元素到栈顶：取出栈顶元素作为深度 n，然后获取深度 n 的元素，并复制到栈顶。
            // `[x0,x1,x2,x3,x4,x5=3] -> [x0,x1,x2,x3,x4,x2]`
            Stack::OpPick => {
                let depth = self.pick_or_roll_depth()?;
                let value = self.top_n(depth)?;
                self.push(value)?;
            }

            // Roll:移动指定深度的元素到栈顶：取出栈顶元素作为深度 n，然后获取深度 n 的元素，并移动到栈顶。
            // `[x0,x1,x2,x3,x4,x5=3] -> [x0,x2,x3,x4,x2]`
            Stack::OpRoll => {
                let depth = self.pick_or_roll_depth()?;
                let value = self.remove_top_n(depth)?;
                self.push(value)?;
            }
        }
        Ok(())
    }
    // ----Splice-----
    fn exec_splice_ops(&mut self, op: Splice) -> Result<(), ScriptError> {
        match op {
            //拼接两个字节串 `[x1, x2] -> [x1 || x2]`
            Splice::OpCat => {
                self.require_stack(2)?;
                let (right, mut left) = (self.pop()?, self.pop()?);
                left.extend_from_slice(right.as_slice());
                self.push(left)?;
            }
            //截取字节串的一段
            //[in, begin, size] -> [in[begin .. begin + size]]
            Splice::OpSubStr => {
                self.require_stack(3)?;
                let (size, begin, input) = (self.pop()?, self.pop()?, self.pop()?);

                let begin = cast_splice_arg_to_usize(&begin)?;
                let size = cast_splice_arg_to_usize(&size)?;
                let end = begin
                    .checked_add(size)
                    .ok_or(ScriptError::InvalidSpliceArgument)?;

                // 贴合 v0.3.19 的语义：超过输入长度时 clamp 到输入长度。
                let begin = begin.min(input.len());
                let end = end.min(input.len());
                if begin > end {
                    return Err(ScriptError::InvalidSpliceArgument);
                }
                self.push(input[begin..end].to_vec())?;
            }

            //保留左侧前 size 个字节。
            //[in, size] -> [in[..size]]
            Splice::OpLeft => {
                self.require_stack(2)?;
                let (size, input) = (self.pop()?, self.pop()?);
                let size = cast_splice_arg_to_usize(&size)?.min(input.len());
                self.push(input[..size].to_vec())?;
            }

            //保留右侧后 size 个字节。
            //[in, size] -> [in[in.len() - size ..]]
            Splice::OpRight => {
                self.require_stack(2)?;
                let (size, input) = (self.pop()?, self.pop()?);
                let size = cast_splice_arg_to_usize(&size)?.min(input.len());
                self.push(input[input.len() - size..].to_vec())?;
            }

            //读取栈顶元素长度，并把长度压栈，但不移除原元素。
            // [in] -> [in, len(in)]
            Splice::OpSize => {
                self.require_stack(1)?;
                let top = self.top()?; //读取栈顶，不弹出
                let len = BigNum::from_usize(top.len());
                self.push_bignum(len)?;
            }
        }
        Ok(())
    }
    // ----BitLogic-----
    fn exec_bit_logic_ops(&mut self, op: BitLogic) -> Result<(), ScriptError> {
        match op {
            // 逻辑：非
            BitLogic::OpInvert => {
                self.require_stack(1)?;
                let mut value = self.pop()?;
                for byte in &mut value {
                    *byte = !*byte;
                }
                self.push(value)?;
            }
            // 逻辑：与
            BitLogic::OpAnd => {
                self.require_stack(2)?;
                let right = self.pop()?;
                let left = self.pop()?;
                self.push(bit_logic_binary_op(left, right, |a, b| a & b))?;
            }
            // 逻辑:或
            BitLogic::OpOr => {
                self.require_stack(2)?;
                let (right, left) = (self.pop()?, self.pop()?);

                self.push(bit_logic_binary_op(left, right, |a, b| a | b))?;
            }
            //逻辑：异或
            BitLogic::OpXor => {
                self.require_stack(2)?;
                let (right, left) = (self.pop()?, self.pop()?);
                self.push(bit_logic_binary_op(left, right, |a, b| a ^ b))?;
            }
            // 逻辑：等
            BitLogic::OpEqual => {
                self.require_stack(2)?;
                let (right, left) = (self.pop()?, self.pop()?);

                self.push(cast_bool_to_script_num(left == right))?;
            }
            //等价于先执行 OP_EQUAL，再执行 OP_VERIFY。
            BitLogic::OpEqualVerify => {
                self.require_stack(2)?;
                let (right, left) = (self.pop()?, self.pop()?);

                if left != right {
                    return Err(ScriptError::EqualVerifyFailed);
                }
            }
            BitLogic::OpReserved1 => {
                return Err(ScriptError::ReservedOpcode(op.byte()));
            }
            BitLogic::OpReserved2 => {
                return Err(ScriptError::ReservedOpcode(op.byte()));
            }
        }
        Ok(())
    }
    // ----Numeric-----
    fn exec_numeric_ops(&mut self, op: Numeric) -> Result<(), ScriptError> {
        //原版 Numeric 分三类：一元数值运算、二元数值/比较运算、三元 OP_WITHIN
        match op {
            // 一元运算符，取出栈顶元素，转数值，加1
            Numeric::Op1Add => {
                let n = self.pop_bignum_from_script_num()?;
                self.push_bignum(n.add_one())?;
            }
            // 一元运算符，取出栈顶元素，转数值，减1
            Numeric::Op1Sub => {
                let n = self.pop_bignum_from_script_num()?;
                self.push_bignum(n.sub_one())?;
            }
            // 一元运算符，取出栈顶元素，转数值，乘2
            Numeric::Op2Mul => {
                let n = self.pop_bignum_from_script_num()?;
                self.push_bignum(n.mul_two())?;
            }
            // 一元运算，取栈顶元素，转数值，除2
            Numeric::Op2Div => {
                let n = self.pop_bignum_from_script_num()?;
                self.push_bignum(n >> 1)?;
            }
            // 一元运算，取负数
            Numeric::OpNegate => {
                let n = self.pop_bignum_from_script_num()?;
                self.push_bignum(n.negate())?;
            }
            // 一元运算，绝对值
            Numeric::OpAbs => {
                let n = self.pop_bignum_from_script_num()?;
                self.push_bignum(n.abs())?;
            }
            // 一元运算，数字等于 0 输出 true，否则 false。
            Numeric::OpNot => {
                let n = self.pop_bignum_from_script_num()?;
                self.push_bool(n.is_zero())?;
            }
            // 一元运算，数字不等于 0 输出 true，否则 false
            Numeric::Op0NotEqual => {
                let n = self.pop_bignum_from_script_num()?;
                self.push_bool(n.is_not_zero())?;
            }
            // 二元运算，left+right
            Numeric::OpAdd => {
                let (left, right) = self.pop2_bignum_from_script_bytes()?;
                self.push_bignum(left + right)?;
            }
            // 二元运算，left-right
            Numeric::OpSub => {
                let (left, right) = self.pop2_bignum_from_script_bytes()?;
                self.push_bignum(left - right)?;
            }
            // 二元运算，left * right
            Numeric::OpMul => {
                let (left, right) = self.pop2_bignum_from_script_bytes()?;
                self.push_bignum(left * right)?;
            }

            // 二元运算，left/right
            Numeric::OpDiv => {
                let (left, right) = self.pop2_bignum_from_script_bytes()?;
                if right.is_zero() {
                    return Err(ScriptError::DivisionByZero);
                }
                self.push_bignum(left / right)?;
            }
            // 二元运算，left % right
            Numeric::OpMod => {
                let (left, right) = self.pop2_bignum_from_script_bytes()?;
                if right.is_zero() {
                    return Err(ScriptError::DivisionByZero);
                }
                self.push_bignum(left % right)?;
            }
            // 二元运算，位运算，左移，原版限制 shift 在 0..=2048
            Numeric::OpLShift => {
                let (left, right) = self.pop2_bignum_from_script_bytes()?;
                let shift = numeric_shift(right)?;
                self.push_bignum(left << shift)?;
            }
            // 二元运算，位运算，右移，原版限制 shift 在 0..=2048
            Numeric::OpRShift => {
                let (left, right) = self.pop2_bignum_from_script_bytes()?;
                let shift = numeric_shift(right)?;
                self.push_bignum(left >> shift)?;
            }
            // 二元运算，把两个数字按“是否非零”解释成布尔值。
            Numeric::OpBoolAnd => {
                let (left, right) = self.pop2_bignum_from_script_bytes()?;
                self.push_bool(left.to_bool() && right.to_bool())?;
            }
            // 二元运算，把两个数字按“是否非零”解释成布尔值。
            Numeric::OpBoolOr => {
                let (left, right) = self.pop2_bignum_from_script_bytes()?;
                self.push_bool(left.to_bool() || right.to_bool())?;
            }
            // 二元运算，数值相等/不相等，不是字节相等。
            Numeric::OpNumEqual => {
                let (left, right) = self.pop2_bignum_from_script_bytes()?;
                self.push_bool(left == right)?;
            }
            //二元运算，数值相等则消耗两个元素且不压栈，不相等返回错误 VerifyFailed。
            Numeric::OpNumEqualVerify => {
                let (left, right) = self.pop2_bignum_from_script_bytes()?;
                if left != right {
                    return Err(ScriptError::VerifyFailed);
                }
            }
            // 二元运算，数值相等/不相等，不是字节相等。
            Numeric::OpNumNotEqual => {
                let (left, right) = self.pop2_bignum_from_script_bytes()?;
                self.push_bool(left != right)?;
            }
            // 二元运算，比大小 left<right
            Numeric::OpLessThan => {
                let (left, right) = self.pop2_bignum_from_script_bytes()?;
                self.push_bool(left < right)?;
            }
            // 二元运算，比大小 left>right
            Numeric::OpGreaterThan => {
                let (left, right) = self.pop2_bignum_from_script_bytes()?;
                self.push_bool(left > right)?;
            }
            // 二元运算，比大小 left <= right
            Numeric::OpLessThanOrEqual => {
                let (left, right) = self.pop2_bignum_from_script_bytes()?;
                self.push_bool(left <= right)?;
            }
            // 二元运算，比大小 left >= right
            Numeric::OpGreaterThanOrEqual => {
                let (left, right) = self.pop2_bignum_from_script_bytes()?;
                self.push_bool(left >= right)?;
            }
            // 二元运算，取最小值
            Numeric::OpMin => {
                let (left, right) = self.pop2_bignum_from_script_bytes()?;
                self.push_bignum(left.min(right))?;
            }
            // 二元运算，取最大值
            Numeric::OpMax => {
                let (left, right) = self.pop2_bignum_from_script_bytes()?;
                self.push_bignum(left.max(right))?;
            }
            // 三元运算，判断 min <= value < max
            Numeric::OpWithin => {
                self.require_stack(3)?;
                let max = self.pop_bignum_from_script_num()?;
                let min = self.pop_bignum_from_script_num()?;
                let value = self.pop_bignum_from_script_num()?;
                self.push_bool(min <= value && value < max)?;
            }
        }
        Ok(())
    }
    // ----Crypto-----
    fn exec_crypto_ops(&mut self, op: Crypto) -> Result<(), ScriptError> {
        match op {
            // [in] -> [RIPEMD160(in)] 检查栈至少 1 个元素，取栈顶字节串，计算 RIPEMD160，弹出原值，压入 hash
            Crypto::OpRipemd160 => {
                self.require_stack(1)?;
                let data = self.pop()?;
                let value = hash160(&data);
                self.push(value.to_vec())?
            }
            Crypto::OpSha1 => {}
            Crypto::OpSha256 => {}
            Crypto::OpHash160 => {}
            Crypto::OpHash256 => {}
            Crypto::OpCodeSeparator => {}
            Crypto::OpCheckSig => {}
            Crypto::OpCheckSigVerify => {}
            Crypto::OpCheckMultiSig => {}
            Crypto::OpCheckMultiSigVerify => {}
        }
        Ok(())
    }
    // ----Expansion-----
    fn exec_expansion_ops(&mut self, op: Expansion) -> Result<(), ScriptError> {
        match op {
            Expansion::OpNop1 => {}
            Expansion::OpNop2 => {}
            Expansion::OpNop3 => {}
            Expansion::OpNop4 => {}
            Expansion::OpNop5 => {}
            Expansion::OpNop6 => {}
            Expansion::OpNop7 => {}
            Expansion::OpNop8 => {}
            Expansion::OpNop9 => {}
            Expansion::OpNop10 => {}
            Expansion::OpCheckSigAdd => {}
        }
        Ok(())
    }

    //-----//
    fn should_execute(&self) -> bool {
        !self.vf_exec.iter().any(|&v| !v)
    }

    /// OP_PICK / OP_ROLL 都先从栈顶弹出一个 ScriptNumType，作为目标元素的深度 n。
    ///
    /// n = 0 表示当前栈顶；n = 1 表示栈顶下面一个元素。
    ///
    /// 弹出 n 之后，n 表示在剩余主栈中从栈顶向下数的深度。
    ///
    /// 返回：栈顶深度，n = 0 表示剩余主栈的当前栈顶。
    fn pick_or_roll_depth(&mut self) -> Result<usize, ScriptError> {
        self.require_stack(2)?;
        let n = self.pop_bignum_from_script_num()?;
        let n = n.to_i64().map_err(|_| ScriptError::InvalidDataTypeCast)?;
        let len = self.stack_len();
        if n >= len as i64 || n < 0 {
            return Err(ScriptError::InvalidStackIndex { index: n, len });
        }

        Ok(n as usize)
    }

    fn pop_bignum_from_script_num(&mut self) -> Result<BigNum, ScriptError> {
        self.require_stack(1)?;
        let value = self.pop()?;
        cast_script_num_to_bignum(&value)
    }

    fn pop2_bignum_from_script_bytes(&mut self) -> Result<(BigNum, BigNum), ScriptError> {
        self.require_stack(2)?;
        let right = self.pop_bignum_from_script_num()?;
        let left = self.pop_bignum_from_script_num()?;
        Ok((left, right))
    }

    fn push_bignum(&mut self, value: BigNum) -> Result<(), ScriptError> {
        self.push(cast_bignum_to_script_num(value))
    }

    fn push_bool(&mut self, value: bool) -> Result<(), ScriptError> {
        self.push(cast_bool_to_script_num(value))
    }
}

fn is_conditional_control_op(op: Control) -> bool {
    matches!(
        op,
        Control::OpIf
            | Control::OpNotIf
            | Control::OpElse
            | Control::OpVerIf
            | Control::OpVerNotIf
            | Control::OpEndIf
    )
}

/// 工具函数:对两个栈元素执行逐字节位运算。
///
/// 参考 v0.3.19 的 `MakeSameSize`：如果两个字节串长度不同，先把较短的一方
/// 在尾部补 `0x00` 到相同长度，再逐字节执行 `f`，此为归一化。
///
/// 这里处理的是原始字节串，不是先转换成 ScriptNum 后再计算。
/// 例如 `[0x03, 0x02, 0x01]` 和 `[0x02, 0x01]`
/// 会先变成 `[0x03, 0x02, 0x01]` 和 `[0x02, 0x01, 0x00]`。
fn bit_logic_binary_op<F>(mut left: Vec<u8>, mut right: Vec<u8>, f: F) -> Vec<u8>
where
    F: Fn(u8, u8) -> u8,
{
    let max_len = max(left.len(), right.len());
    left.resize(max_len, 0u8);
    right.resize(max_len, 0u8);
    left.iter()
        .zip(right.iter())
        .map(|(&l, &r)| f(l, r))
        .collect()
}

/// 数值转化: BigNum -> scriptnum
///
/// 调用BigNum的to_bytes_le方法，注意小端序、正负号和零的处理
fn cast_bignum_to_script_num(value: BigNum) -> ScriptNumType {
    value.to_bytes_le()
}

/// 数值转化：scriptnum -> BigNum
///
/// 对应原版中 script.cpp CastToBigNum 函数
///
/// ```cpp
/// CBigNum CastToBigNum(const valtype& vch)
/// {
///     if (vch.size() > nMaxNumSize)
///         throw runtime_error("CastToBigNum() : overflow");
///     return CBigNum(CBigNum(vch).getvch());
/// }
/// ```
/// 将脚本字节流转成BigNum符合原版比特币语义：无精度、有符号、小端序,参考`BigNum::from_bytes_le`实现
///
fn cast_script_num_to_bignum(v: &[u8]) -> Result<BigNum, ScriptError> {
    if v.len() > MAX_SCRIPT_NUM_SIZE {
        return Err(ScriptError::ScriptNumOverflow {
            max: MAX_SCRIPT_NUM_SIZE,
            actual: v.len(),
        });
    }
    Ok(BigNum::from_bytes_le(v))
}

/// Splice 参数最终要作为 Rust 切片下标使用，因此必须是非负且能放进 usize。
fn cast_splice_arg_to_usize(v: &[u8]) -> Result<usize, ScriptError> {
    let n = cast_script_num_to_bignum(v)?;
    match n.is_negative() {
        true => Err(ScriptError::InvalidSpliceArgument),
        false => n.to_usize().map_err(|_| ScriptError::InvalidDataTypeCast),
    }
}

/// 原版对 OP_LSHIFT / OP_RSHIFT 的位移量限制为 0..=2048。
fn numeric_shift(n: BigNum) -> Result<u32, ScriptError> {
    match n.is_negative() || n > BigNum::from_u32(2048) {
        true => Err(ScriptError::InvalidNumericShift {
            shift: n.to_string(),
        }),
        false => n.to_u32().map_err(|_| ScriptError::InvalidDataTypeCast),
    }
}

/// Bitcoin Script 的布尔值不是独立类型，而是从栈元素字节解释出来。
///
/// false 的情况：空向量、所有字节都是 0、负零。
///
/// 负零的典型形式是 `[0x80]`，也可能是 `[0x00, 0x80]` 这类“只有符号位非零”的形式。
///
/// 因此这里从低位到高位扫描：遇到普通非零字节就是真；如果唯一非零字节是最后一个字节的 0x80，则是假。
///
/// 实际例子：
///
/// | ScriptNumType | bool |
/// | --- | --- |
/// | `[]` | `false` |
/// | `[0x00]` | `false` |
/// | `[0x00, 0x00]` | `false` |
/// | `[0x80]` | `false` |
/// | `[0x00, 0x80]` | `false` |
/// | `[0x01]` | `true` |
/// | `[0x81]` | `true` |
/// | `[0x80, 0x00]` | `true` |
fn cast_script_num_to_bool(v: &[u8]) -> bool {
    for (index, byte) in v.iter().enumerate() {
        if *byte == 0 {
            continue;
        }
        return !(index == v.len() - 1 && *byte == 0x80);
    }
    false
}

/// 转化boo -> script num
///
/// true -> `[0x01]`
///
/// false -> `[]`
fn cast_bool_to_script_num(value: bool) -> ScriptNumType {
    if value {
        vec![0x01]
    } else {
        Vec::new() //依据原版 vchFalse(0) 是空向量，不是 [0x00]。
    }
}
