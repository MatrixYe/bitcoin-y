use bitcoin_y::script::interpreter::Interpreter;
use bitcoin_y::script::opcode::{Numeric, OpCode};
use bitcoin_y::script::parser::ScriptToken;
use bitcoin_y::script::rules::RuleOpen;
use bitcoin_y::script::ScriptError;

fn numeric_op(op: Numeric) -> ScriptToken {
    ScriptToken::Command(OpCode::Numeric(op))
}

fn open_interpreter(stack: Vec<Vec<u8>>) -> Interpreter<RuleOpen> {
    Interpreter::with_stack_and_rules(stack, RuleOpen)
}

fn num(value: i64) -> Vec<u8> {
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

    let last = result.len() - 1;
    if result[last] & 0x80 != 0 {
        result.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        result[last] |= 0x80;
    }
    result
}

// 测试一元 Numeric 操作码：输入一个 ScriptNum，输出一个 ScriptNum 或布尔 ScriptNum。
#[test]
fn execute_unary_numeric_ops() {
    let cases = [
        (Numeric::Op1Add, 2, 3),
        (Numeric::Op1Sub, 2, 1),
        (Numeric::Op2Mul, 3, 6),
        (Numeric::Op2Div, 7, 3),
        (Numeric::OpNegate, 5, -5),
        (Numeric::OpAbs, -5, 5),
        (Numeric::OpNot, 0, 1),
        (Numeric::OpOp0NotEqual, 7, 1),
    ];

    for (op, input, expected) in cases {
        let mut interpreter = open_interpreter(vec![num(input)]);
        interpreter.execute(&[numeric_op(op)]).unwrap();
        assert_eq!(interpreter.stack, vec![num(expected)]);
    }
}

// 测试二元算术操作码：栈形态为 [left, right]，结果按 left op right 计算。
#[test]
fn execute_binary_arithmetic_numeric_ops() {
    let cases = [
        (Numeric::OpAdd, 7, 3, 10),
        (Numeric::OpSub, 7, 3, 4),
        (Numeric::OpMul, 7, 3, 21),
        (Numeric::OpDiv, 7, 3, 2),
        (Numeric::OpMod, 7, 3, 1),
        (Numeric::OpLShift, 3, 2, 12),
        (Numeric::OpRShift, 12, 2, 3),
        (Numeric::OpMin, 7, 3, 3),
        (Numeric::OpMax, 7, 3, 7),
    ];

    for (op, left, right, expected) in cases {
        let mut interpreter = open_interpreter(vec![num(left), num(right)]);
        interpreter.execute(&[numeric_op(op)]).unwrap();
        assert_eq!(interpreter.stack, vec![num(expected)]);
    }
}

// 测试布尔和比较 Numeric 操作码：结果使用 Bitcoin Script 布尔编码，[1] 或 []。
#[test]
fn execute_boolean_and_compare_numeric_ops() {
    let cases = [
        (Numeric::OpBoolAnd, 1, 2, 1),
        (Numeric::OpBoolOr, 0, 2, 1),
        (Numeric::OpNumEqual, 2, 2, 1),
        (Numeric::OpNumNotEqual, 2, 3, 1),
        (Numeric::OpLessThan, 2, 3, 1),
        (Numeric::OpGreaterThan, 3, 2, 1),
        (Numeric::OpLessThanOrEqual, 2, 2, 1),
        (Numeric::OpGreaterThanOrEqual, 2, 2, 1),
    ];

    for (op, left, right, expected) in cases {
        let mut interpreter = open_interpreter(vec![num(left), num(right)]);
        interpreter.execute(&[numeric_op(op)]).unwrap();
        assert_eq!(interpreter.stack, vec![num(expected)]);
    }
}

// 测试 OP_NUMEQUALVERIFY：相等时消耗两个元素，不相等时失败。
#[test]
fn execute_num_equal_verify() {
    let mut interpreter = open_interpreter(vec![num(5), num(5)]);
    interpreter
        .execute(&[numeric_op(Numeric::OpNumEqualVerify)])
        .unwrap();
    assert_eq!(interpreter.stack, Vec::<Vec<u8>>::new());

    let mut interpreter = open_interpreter(vec![num(5), num(6)]);
    let err = interpreter
        .execute(&[numeric_op(Numeric::OpNumEqualVerify)])
        .unwrap_err();
    assert_eq!(err, ScriptError::VerifyFailed);
}

// 测试 OP_WITHIN：判断 min <= value < max。
#[test]
fn execute_within_numeric_op() {
    let mut interpreter = open_interpreter(vec![num(5), num(3), num(8)]);
    interpreter.execute(&[numeric_op(Numeric::OpWithin)]).unwrap();
    assert_eq!(interpreter.stack, vec![num(1)]);

    let mut interpreter = open_interpreter(vec![num(8), num(3), num(8)]);
    interpreter.execute(&[numeric_op(Numeric::OpWithin)]).unwrap();
    assert_eq!(interpreter.stack, vec![num(0)]);
}

// 测试错误路径：除数为 0 和非法移位参数。
#[test]
fn execute_numeric_ops_return_errors_for_invalid_arguments() {
    let mut interpreter = open_interpreter(vec![num(7), num(0)]);
    let err = interpreter.execute(&[numeric_op(Numeric::OpDiv)]).unwrap_err();
    assert_eq!(err, ScriptError::DivisionByZero);

    let mut interpreter = open_interpreter(vec![num(7), num(-1)]);
    let err = interpreter
        .execute(&[numeric_op(Numeric::OpLShift)])
        .unwrap_err();
    assert_eq!(err, ScriptError::InvalidNumericShift { shift: -1 });
}

// 测试规则层：默认规则禁用部分 Numeric 操作码，但 RuleOpen 会执行真实语义。
#[test]
fn execute_disabled_numeric_ops_are_controlled_by_rules() {
    let mut interpreter = Interpreter::with_stack(vec![num(2), num(3)]);
    let err = interpreter.execute(&[numeric_op(Numeric::OpMul)]).unwrap_err();
    assert_eq!(err, ScriptError::DisabledOpcode(Numeric::OpMul.byte()));

    let mut interpreter = open_interpreter(vec![num(2), num(3)]);
    interpreter.execute(&[numeric_op(Numeric::OpMul)]).unwrap();
    assert_eq!(interpreter.stack, vec![num(6)]);
}
