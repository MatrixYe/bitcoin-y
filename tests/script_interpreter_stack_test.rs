use bitcoin_y::script::interpreter::Interpreter;
use bitcoin_y::script::opcode::{OpCode, StackOp};
use bitcoin_y::script::parser::{PushBytesKind, ScriptData, ScriptToken};

fn byte(value: u8) -> Vec<u8> {
    vec![value]
}

fn stack_op(op: StackOp) -> ScriptToken {
    ScriptToken::Command(OpCode::Stack(op))
}

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

#[test]
fn execute_depth_pushes_script_num_encoded_stack_size() {
    let mut interpreter = Interpreter::with_stack(vec![byte(1), byte(2)]);
    interpreter.execute(&[stack_op(StackOp::Depth)]).unwrap();
    assert_eq!(interpreter.stack, vec![byte(1), byte(2), byte(2)]);
}

#[test]
fn execute_pick_and_roll_use_script_num_index() {
    let mut interpreter = Interpreter::with_stack(vec![byte(1), byte(2), byte(3), byte(1)]);
    interpreter.execute(&[stack_op(StackOp::Pick)]).unwrap();
    assert_eq!(interpreter.stack, vec![byte(1), byte(2), byte(3), byte(2)]);

    let mut interpreter = Interpreter::with_stack(vec![byte(1), byte(2), byte(3), byte(1)]);
    interpreter.execute(&[stack_op(StackOp::Roll)]).unwrap();
    assert_eq!(interpreter.stack, vec![byte(1), byte(3), byte(2)]);
}

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
}
