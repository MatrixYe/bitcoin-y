use bitcoin_y::script::interpreter::Interpreter;
use bitcoin_y::script::opcode::{BitLogic, OpCode};
use bitcoin_y::script::parser::ScriptToken;
use bitcoin_y::script::ScriptError;

fn bit_logic_op(op: BitLogic) -> ScriptToken {
    ScriptToken::Command(OpCode::BitLogic(op))
}

// 测试 OP_EQUAL：两个栈元素原始字节完全相等时，压入 true，即 [0x01]。
#[test]
fn execute_op_equal_pushes_true_when_bytes_are_equal() {
    let mut interpreter = Interpreter::with_stack(vec![vec![1, 2], vec![1, 2]]);
    interpreter.execute(&[bit_logic_op(BitLogic::OpEqual)]).unwrap();
    assert_eq!(interpreter.stack, vec![vec![0x01]]);
}

// 测试 OP_EQUAL：两个栈元素原始字节不相等时，压入 false，即空向量。
#[test]
fn execute_op_equal_pushes_false_when_bytes_are_not_equal() {
    let mut interpreter = Interpreter::with_stack(vec![vec![1], vec![2]]);
    interpreter.execute(&[bit_logic_op(BitLogic::OpEqual)]).unwrap();
    assert_eq!(interpreter.stack, vec![Vec::<u8>::new()]);
}

// 测试 OP_EQUAL 的字节语义：[0x01] 和 [0x01, 0x00] 数值上都可解释为 1，但字节不相等。
#[test]
fn execute_op_equal_compares_raw_bytes_not_numeric_values() {
    let mut interpreter = Interpreter::with_stack(vec![vec![0x01], vec![0x01, 0x00]]);
    interpreter.execute(&[bit_logic_op(BitLogic::OpEqual)]).unwrap();
    assert_eq!(interpreter.stack, vec![Vec::<u8>::new()]);
}

// 测试 OP_EQUAL 的错误路径：栈内元素不足两个时返回 StackUnderflow。
#[test]
fn execute_op_equal_requires_two_stack_items() {
    let mut interpreter = Interpreter::with_stack(vec![vec![1]]);
    let err = interpreter.execute(&[bit_logic_op(BitLogic::OpEqual)]).unwrap_err();
    assert_eq!(err, ScriptError::StackUnderflow);
}

// 测试 OP_EQUALVERIFY：两个栈元素字节相等时，消耗两个元素且不压入布尔值。
#[test]
fn execute_op_equalverify_succeeds_when_bytes_are_equal() {
    let mut interpreter = Interpreter::with_stack(vec![vec![1, 2], vec![1, 2]]);
    interpreter
        .execute(&[bit_logic_op(BitLogic::OpEqualVerify)])
        .unwrap();
    assert_eq!(interpreter.stack, Vec::<Vec<u8>>::new());
}

// 测试 OP_EQUALVERIFY：两个栈元素字节不相等时返回 EqualVerifyFailed。
#[test]
fn execute_op_equalverify_fails_when_bytes_are_not_equal() {
    let mut interpreter = Interpreter::with_stack(vec![vec![1], vec![2]]);
    let err = interpreter
        .execute(&[bit_logic_op(BitLogic::OpEqualVerify)])
        .unwrap_err();
    assert_eq!(err, ScriptError::EqualVerifyFailed);
}

// 测试禁用的位逻辑操作码：即使语义清晰，当前执行路径仍返回 DisabledOpcode。
#[test]
fn execute_disabled_bit_logic_ops_return_disabled_opcode() {
    for op in [
        BitLogic::OpInvert,
        BitLogic::OpAnd,
        BitLogic::OpOr,
        BitLogic::OpXor,
    ] {
        let mut interpreter = Interpreter::with_stack(vec![vec![0xff], vec![0x0f]]);
        let err = interpreter.execute(&[bit_logic_op(op)]).unwrap_err();
        assert_eq!(err, ScriptError::DisabledOpcode(op.byte()));
    }
}

// 测试保留的位逻辑操作码：OP_RESERVED1 / OP_RESERVED2 继续作为保留操作码处理。
#[test]
fn execute_reserved_bit_logic_ops_return_reserved_opcode() {
    for op in [BitLogic::OpReserved1, BitLogic::OpReserved2] {
        let mut interpreter = Interpreter::new();
        let err = interpreter.execute(&[bit_logic_op(op)]).unwrap_err();
        assert_eq!(err, ScriptError::ReservedOpcode(op.byte()));
    }
}
