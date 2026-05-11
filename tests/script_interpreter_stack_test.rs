use bitcoin_y::script::interpreter::Interpreter;
use bitcoin_y::script::opcode::{OpCode, StackOp};
use bitcoin_y::script::parser::{PushBytesKind, ScriptData, ScriptToken};
use bitcoin_y::script::ScriptError;

fn byte(value: u8) -> Vec<u8> {
    vec![value]
}

fn stack_op(op: StackOp) -> ScriptToken {
    ScriptToken::Command(OpCode::Stack(op))
}

// 测试 OP_TOALTSTACK / OP_FROMALTSTACK：主栈和备用栈之间移动元素。
#[test]
fn execute_alt_stack_ops_move_between_stacks() {
    let mut interpreter = Interpreter::with_stack(vec![byte(1), byte(2)]);
    interpreter
        .execute(&[stack_op(StackOp::ToAltStack), stack_op(StackOp::FromAltStack)])
        .unwrap();
    assert_eq!(interpreter.stack, vec![byte(1), byte(2)]);
}

// 测试 OP_DUP / OP_2DUP / OP_3DUP / OP_OVER / OP_2OVER / OP_TUCK：复制类栈操作。
#[test]
fn execute_copy_ops_duplicate_expected_stack_items() {
    let mut interpreter = Interpreter::with_stack(vec![byte(1)]);
    interpreter.execute(&[stack_op(StackOp::Dup)]).unwrap();
    assert_eq!(interpreter.stack, vec![byte(1), byte(1)]);

    let mut interpreter = Interpreter::with_stack(vec![byte(1), byte(2)]);
    interpreter.execute(&[stack_op(StackOp::Op2Dup)]).unwrap();
    assert_eq!(interpreter.stack, vec![byte(1), byte(2), byte(1), byte(2)]);

    let mut interpreter = Interpreter::with_stack(vec![byte(1), byte(2), byte(3)]);
    interpreter.execute(&[stack_op(StackOp::Op3Dup)]).unwrap();
    assert_eq!(
        interpreter.stack,
        vec![byte(1), byte(2), byte(3), byte(1), byte(2), byte(3)]
    );

    let mut interpreter = Interpreter::with_stack(vec![byte(1), byte(2)]);
    interpreter.execute(&[stack_op(StackOp::Over)]).unwrap();
    assert_eq!(interpreter.stack, vec![byte(1), byte(2), byte(1)]);

    let mut interpreter = Interpreter::with_stack(vec![byte(1), byte(2), byte(3), byte(4)]);
    interpreter.execute(&[stack_op(StackOp::Op2Over)]).unwrap();
    assert_eq!(
        interpreter.stack,
        vec![byte(1), byte(2), byte(3), byte(4), byte(1), byte(2)]
    );

    let mut interpreter = Interpreter::with_stack(vec![byte(1), byte(2)]);
    interpreter.execute(&[stack_op(StackOp::Tuck)]).unwrap();
    assert_eq!(interpreter.stack, vec![byte(2), byte(1), byte(2)]);
}

// 测试 OP_DROP / OP_2DROP / OP_NIP：删除类栈操作。
#[test]
fn execute_drop_ops_remove_expected_stack_items() {
    let mut interpreter = Interpreter::with_stack(vec![byte(1), byte(2)]);
    interpreter.execute(&[stack_op(StackOp::Drop)]).unwrap();
    assert_eq!(interpreter.stack, vec![byte(1)]);

    let mut interpreter = Interpreter::with_stack(vec![byte(1), byte(2), byte(3)]);
    interpreter.execute(&[stack_op(StackOp::Op2Drop)]).unwrap();
    assert_eq!(interpreter.stack, vec![byte(1)]);

    let mut interpreter = Interpreter::with_stack(vec![byte(1), byte(2)]);
    interpreter.execute(&[stack_op(StackOp::Nip)]).unwrap();
    assert_eq!(interpreter.stack, vec![byte(2)]);
}

// 测试 OP_SWAP / OP_ROT / OP_2SWAP / OP_2ROT：交换和旋转类栈操作。
#[test]
fn execute_swap_ops_reorder_stack() {
    let mut interpreter = Interpreter::with_stack(vec![byte(1), byte(2)]);
    interpreter.execute(&[stack_op(StackOp::Swap)]).unwrap();
    assert_eq!(interpreter.stack, vec![byte(2), byte(1)]);

    let mut interpreter = Interpreter::with_stack(vec![byte(1), byte(2), byte(3)]);
    interpreter.execute(&[stack_op(StackOp::Rot)]).unwrap();
    assert_eq!(interpreter.stack, vec![byte(2), byte(3), byte(1)]);

    let mut interpreter = Interpreter::with_stack(vec![byte(1), byte(2), byte(3), byte(4)]);
    interpreter.execute(&[stack_op(StackOp::Op2Swap)]).unwrap();
    assert_eq!(interpreter.stack, vec![byte(3), byte(4), byte(1), byte(2)]);

    let mut interpreter = Interpreter::with_stack(vec![
        byte(1),
        byte(2),
        byte(3),
        byte(4),
        byte(5),
        byte(6),
    ]);
    interpreter.execute(&[stack_op(StackOp::Op2Rot)]).unwrap();
    assert_eq!(
        interpreter.stack,
        vec![byte(3), byte(4), byte(5), byte(6), byte(1), byte(2)]
    );
}

// 测试 OP_DEPTH：将当前主栈深度按 ScriptNum 编码后压入栈顶。
#[test]
fn execute_depth_pushes_script_num_encoded_stack_size() {
    let mut interpreter = Interpreter::with_stack(vec![byte(1), byte(2)]);
    interpreter.execute(&[stack_op(StackOp::Depth)]).unwrap();
    assert_eq!(interpreter.stack, vec![byte(1), byte(2), byte(2)]);
}

// 测试 OP_PICK / OP_ROLL：使用栈顶 ScriptNum 作为深度索引。
#[test]
fn execute_pick_and_roll_use_script_num_index() {
    let mut interpreter = Interpreter::with_stack(vec![byte(1), byte(2), byte(3), byte(1)]);
    interpreter.execute(&[stack_op(StackOp::Pick)]).unwrap();
    assert_eq!(interpreter.stack, vec![byte(1), byte(2), byte(3), byte(2)]);

    let mut interpreter = Interpreter::with_stack(vec![byte(1), byte(2), byte(3), byte(1)]);
    interpreter.execute(&[stack_op(StackOp::Roll)]).unwrap();
    assert_eq!(interpreter.stack, vec![byte(1), byte(3), byte(2)]);

    let mut interpreter = Interpreter::with_stack(vec![byte(1), byte(2), byte(3), byte(4), byte(3)]);
    interpreter.execute(&[stack_op(StackOp::Pick)]).unwrap();
    assert_eq!(
        interpreter.stack,
        vec![byte(1), byte(2), byte(3), byte(4), byte(1)]
    );

    let mut interpreter = Interpreter::with_stack(vec![byte(1), byte(2), byte(3), byte(4), byte(3)]);
    interpreter.execute(&[stack_op(StackOp::Roll)]).unwrap();
    assert_eq!(interpreter.stack, vec![byte(2), byte(3), byte(4), byte(1)]);
}

// 测试 OP_IFDUP：按 Bitcoin Script 布尔规则决定是否复制栈顶。
#[test]
fn execute_ifdup_uses_bitcoin_bool_rules() {
    let mut interpreter = Interpreter::with_stack(vec![byte(1)]);
    interpreter.execute(&[stack_op(StackOp::IfDup)]).unwrap();
    assert_eq!(interpreter.stack, vec![byte(1), byte(1)]);

    let mut interpreter = Interpreter::with_stack(vec![Vec::new()]);
    interpreter.execute(&[stack_op(StackOp::IfDup)]).unwrap();
    assert_eq!(interpreter.stack, vec![Vec::<u8>::new()]);

    let negative_zero = ScriptToken::Data(ScriptData::Bytes {
        kind: PushBytesKind::Direct(1),
        bytes: vec![0x80],
    });
    let mut interpreter = Interpreter::new();
    interpreter
        .execute(&[negative_zero, stack_op(StackOp::IfDup)])
        .unwrap();
    assert_eq!(interpreter.stack, vec![vec![0x80]]);

    let negative_one = ScriptToken::Data(ScriptData::Bytes {
        kind: PushBytesKind::Direct(1),
        bytes: vec![0x81],
    });
    let mut interpreter = Interpreter::new();
    interpreter
        .execute(&[negative_one, stack_op(StackOp::IfDup)])
        .unwrap();
    assert_eq!(interpreter.stack, vec![vec![0x81], vec![0x81]]);
}

// 测试 StackOp 的错误路径：栈元素不足或索引非法时返回明确错误。
#[test]
fn execute_stack_ops_return_errors_for_invalid_stack_state() {
    let mut interpreter = Interpreter::new();
    let err = interpreter.execute(&[stack_op(StackOp::Drop)]).unwrap_err();
    assert_eq!(err, ScriptError::StackUnderflow);

    let mut interpreter = Interpreter::with_stack(vec![byte(1), byte(2)]);
    let err = interpreter.execute(&[stack_op(StackOp::Op2Swap)]).unwrap_err();
    assert_eq!(err, ScriptError::StackUnderflow);

    let mut interpreter = Interpreter::with_stack(vec![byte(1), byte(2)]);
    let err = interpreter.execute(&[stack_op(StackOp::Pick)]).unwrap_err();
    assert_eq!(err, ScriptError::InvalidStackIndex { index: 2, len: 1 });
}
