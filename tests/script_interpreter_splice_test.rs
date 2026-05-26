use bitcoin_y::script::ScriptError;
use bitcoin_y::script::consts::MAX_SCRIPT_ELEMENT_SIZE;
use bitcoin_y::script::interpreter::Interpreter;
use bitcoin_y::script::opcode::{OpCode, Splice};
use bitcoin_y::script::parser::ScriptToken;
use bitcoin_y::script::rules::RuleOpen;

fn splice_op(op: Splice) -> ScriptToken {
    ScriptToken::Command(OpCode::Splice(op))
}

fn open_interpreter(stack: Vec<Vec<u8>>) -> Interpreter<RuleOpen> {
    Interpreter::with_stack_and_rules(stack, RuleOpen)
}

// 测试 OP_CAT：开放规则下执行真实拼接语义；默认规则下仍由规则层禁用。
#[test]
fn execute_op_cat_concatenates_bytes_when_rule_allows_it() {
    let mut interpreter = open_interpreter(vec![b"hello ".to_vec(), b"world".to_vec()]);
    interpreter.execute(&[splice_op(Splice::OpCat)]).unwrap();
    assert_eq!(interpreter.stack, vec![b"hello world".to_vec()]);

    let mut interpreter = Interpreter::with_stack(vec![b"a".to_vec(), b"b".to_vec()]);
    let err = interpreter
        .execute(&[splice_op(Splice::OpCat)])
        .unwrap_err();
    assert_eq!(err, ScriptError::DisabledOpcode(Splice::OpCat.byte()));
}

// 测试 OP_CAT：拼接结果仍受单个栈元素 520 字节限制。
#[test]
fn execute_op_cat_rejects_too_large_result() {
    let mut interpreter = open_interpreter(vec![vec![0; MAX_SCRIPT_ELEMENT_SIZE], vec![0; 1]]);
    let err = interpreter
        .execute(&[splice_op(Splice::OpCat)])
        .unwrap_err();
    assert_eq!(
        err,
        ScriptError::ElementTooLarge {
            max: MAX_SCRIPT_ELEMENT_SIZE,
            actual: MAX_SCRIPT_ELEMENT_SIZE + 1,
        }
    );
}

// 测试 OP_SUBSTR：按 begin 和 size 截取；超过输入长度时按原版语义 clamp。
#[test]
fn execute_op_substr_slices_and_clamps_bounds() {
    let mut interpreter = open_interpreter(vec![b"abcdef".to_vec(), vec![2], vec![3]]);
    interpreter.execute(&[splice_op(Splice::OpSubStr)]).unwrap();
    assert_eq!(interpreter.stack, vec![b"cde".to_vec()]);

    let mut interpreter = open_interpreter(vec![b"abcdef".to_vec(), vec![4], vec![9]]);
    interpreter.execute(&[splice_op(Splice::OpSubStr)]).unwrap();
    assert_eq!(interpreter.stack, vec![b"ef".to_vec()]);

    let mut interpreter = open_interpreter(vec![b"abcdef".to_vec(), vec![9], vec![2]]);
    interpreter.execute(&[splice_op(Splice::OpSubStr)]).unwrap();
    assert_eq!(interpreter.stack, vec![Vec::<u8>::new()]);
}

// 测试 OP_LEFT / OP_RIGHT：分别保留左侧和右侧 size 个字节，size 超过长度时保留全部。
#[test]
fn execute_op_left_and_right_keep_requested_side() {
    let mut interpreter = open_interpreter(vec![b"abcdef".to_vec(), vec![3]]);
    interpreter.execute(&[splice_op(Splice::OpLeft)]).unwrap();
    assert_eq!(interpreter.stack, vec![b"abc".to_vec()]);

    let mut interpreter = open_interpreter(vec![b"abcdef".to_vec(), vec![3]]);
    interpreter.execute(&[splice_op(Splice::OpRight)]).unwrap();
    assert_eq!(interpreter.stack, vec![b"def".to_vec()]);

    let mut interpreter = open_interpreter(vec![b"abcdef".to_vec(), vec![9]]);
    interpreter.execute(&[splice_op(Splice::OpLeft)]).unwrap();
    assert_eq!(interpreter.stack, vec![b"abcdef".to_vec()]);

    let mut interpreter = open_interpreter(vec![b"abcdef".to_vec(), vec![9]]);
    interpreter.execute(&[splice_op(Splice::OpRight)]).unwrap();
    assert_eq!(interpreter.stack, vec![b"abcdef".to_vec()]);
}

// 测试负数参数：Splice 的位置/长度参数不能为负。
#[test]
fn execute_splice_ops_reject_negative_indexes() {
    let mut interpreter = open_interpreter(vec![b"abcdef".to_vec(), vec![0x81]]);
    let err = interpreter
        .execute(&[splice_op(Splice::OpLeft)])
        .unwrap_err();
    assert_eq!(err, ScriptError::InvalidSpliceArgument);

    let mut interpreter = open_interpreter(vec![b"abcdef".to_vec(), vec![0], vec![0x81]]);
    let err = interpreter
        .execute(&[splice_op(Splice::OpSubStr)])
        .unwrap_err();
    assert_eq!(err, ScriptError::InvalidSpliceArgument);

    let mut interpreter = open_interpreter(vec![b"abcdef".to_vec(), vec![10], vec![0x85]]);
    let err = interpreter
        .execute(&[splice_op(Splice::OpSubStr)])
        .unwrap_err();
    assert_eq!(err, ScriptError::InvalidSpliceArgument);
}

// 测试 OP_SIZE：不移除原栈顶，只把字节长度按 ScriptNum 编码后压栈。
#[test]
fn execute_op_size_keeps_input_and_pushes_byte_len() {
    let mut interpreter = open_interpreter(vec![b"abcd".to_vec()]);
    interpreter.execute(&[splice_op(Splice::OpSize)]).unwrap();
    assert_eq!(interpreter.stack, vec![b"abcd".to_vec(), vec![4]]);
}
