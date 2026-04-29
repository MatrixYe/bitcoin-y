/// @Name: interpreter
///
/// @Date: 2026/4/24 02:57
///
/// @Author: Matrix.Ye
///
/// @Description: 栈机执行引擎
///
use crate::script::error::ScriptError;
use crate::script::parser::Instruction;


/// 栈中的一个元素。
///
/// Bitcoin Script 是字节栈机，签名、公钥、哈希、数字、布尔值都会先表示为字节数组。
pub type StackElement = Vec<u8>;

/// 脚本执行栈。
pub type Stack = Vec<StackElement>;

#[derive(Debug, Clone, Default)]
pub struct Interpreter {
    /// 主栈，对应 Bitcoin Core v0.3.19 `EvalScript` 中的 `stack`。
    stack: Stack,

    /// 备用栈，对应 `OP_TOALTSTACK` / `OP_FROMALTSTACK` 使用的 `altstack`。
    alt_stack: Stack,

    /// 条件执行栈，对应 v0.3.19 中的 `vfExec`。
    ///
    /// 第一阶段可以暂时不用，后续实现 `OP_IF` / `OP_ELSE` / `OP_ENDIF` 时再接入。
    exec_stack: Vec<bool>,

    /// 非 push 操作码计数，对应 v0.3.19 中的 `nOpCount`。
    op_count: usize,
}

impl Interpreter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_stack(stack: Stack) -> Self {
        Self {
            stack,
            ..Self::default()
        }
    }

    pub fn stack(&self) -> &[StackElement] {
        &self.stack
    }

    pub fn stack_mut(&mut self) -> &mut Stack {
        &mut self.stack
    }

    pub fn into_stack(self) -> Stack {
        self.stack
    }

    pub fn alt_stack(&self) -> &[StackElement] {
        &self.alt_stack
    }

    pub fn op_count(&self) -> usize {
        self.op_count
    }

    pub fn execute(&mut self, instructions: &[Instruction]) -> Result<(), ScriptError> {
        let _ = instructions;
        todo!()
    }
}
