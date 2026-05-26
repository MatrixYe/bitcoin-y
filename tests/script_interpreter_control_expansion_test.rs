use bitcoin_y::script::ScriptError;
use bitcoin_y::script::interpreter::Interpreter;
use bitcoin_y::script::opcode::{Control, Expansion, Invalid, Numeric, OpCode};
use bitcoin_y::script::parser::ScriptToken;
use bitcoin_y::script::rules::RuleOpen;

fn command(opcode: OpCode) -> ScriptToken {
    ScriptToken::Command(opcode)
}

fn control_op(op: Control) -> ScriptToken {
    command(OpCode::Control(op))
}

fn expansion_op(op: Expansion) -> ScriptToken {
    command(OpCode::Expansion(op))
}

fn numeric_op(op: Numeric) -> ScriptToken {
    command(OpCode::Numeric(op))
}

fn open_interpreter(stack: Vec<Vec<u8>>) -> Interpreter<RuleOpen> {
    Interpreter::with_stack_and_rules(stack, RuleOpen)
}

fn num(value: u8) -> Vec<u8> {
    match value {
        0 => Vec::new(),
        n => vec![n],
    }
}

#[test]
fn execute_if_skips_non_executed_branch() {
    let mut interpreter = open_interpreter(vec![num(1), num(2), num(0)]);
    interpreter
        .execute(&[
            control_op(Control::OpIf),
            numeric_op(Numeric::OpAdd),
            control_op(Control::OpEndIf),
        ])
        .unwrap();

    assert_eq!(interpreter.stack, vec![num(1), num(2)]);
}

#[test]
fn execute_else_toggles_current_branch() {
    let mut interpreter = open_interpreter(vec![num(2), num(3), num(0)]);
    interpreter
        .execute(&[
            control_op(Control::OpIf),
            numeric_op(Numeric::OpSub),
            control_op(Control::OpElse),
            numeric_op(Numeric::OpAdd),
            control_op(Control::OpEndIf),
        ])
        .unwrap();

    assert_eq!(interpreter.stack, vec![num(5)]);
}

#[test]
fn execute_verify_consumes_true_and_rejects_false() {
    let mut interpreter = open_interpreter(vec![num(1)]);
    interpreter
        .execute(&[control_op(Control::OpVerify)])
        .unwrap();
    assert_eq!(interpreter.stack, Vec::<Vec<u8>>::new());

    let mut interpreter = open_interpreter(vec![num(0)]);
    let err = interpreter
        .execute(&[control_op(Control::OpVerify)])
        .unwrap_err();
    assert_eq!(err, ScriptError::VerifyFailed);
}

#[test]
fn execute_control_ops_return_errors_for_reserved_and_unbalanced_flow() {
    let mut interpreter = open_interpreter(vec![]);
    let err = interpreter
        .execute(&[control_op(Control::OpVer)])
        .unwrap_err();
    assert_eq!(err, ScriptError::ReservedOpcode(Control::OpVer.byte()));

    let mut interpreter = open_interpreter(vec![]);
    let err = interpreter
        .execute(&[control_op(Control::OpElse)])
        .unwrap_err();
    assert_eq!(err, ScriptError::UnbalancedConditional);

    let mut interpreter = open_interpreter(vec![num(1)]);
    let err = interpreter
        .execute(&[control_op(Control::OpIf)])
        .unwrap_err();
    assert_eq!(err, ScriptError::UnclosedConditional);
}

#[test]
fn execute_op_return_fails_script() {
    let mut interpreter = open_interpreter(vec![]);
    let err = interpreter
        .execute(&[control_op(Control::OpReturn)])
        .unwrap_err();
    assert_eq!(err, ScriptError::OpReturn);
}

#[test]
fn execute_expansion_nops_do_nothing_and_signature_opcode_is_deferred() {
    let mut interpreter = open_interpreter(vec![num(7)]);
    interpreter
        .execute(&[
            expansion_op(Expansion::OpNop1),
            expansion_op(Expansion::OpNop2),
            expansion_op(Expansion::OpNop10),
        ])
        .unwrap();
    assert_eq!(interpreter.stack, vec![num(7)]);

    let mut interpreter = open_interpreter(vec![]);
    let err = interpreter
        .execute(&[expansion_op(Expansion::OpCheckSigAdd)])
        .unwrap_err();
    assert_eq!(err, ScriptError::UnsupportedScriptForm);
}

#[test]
fn execute_invalid_opcode_returns_invalid_opcode_error() {
    let mut interpreter = open_interpreter(vec![]);
    let err = interpreter
        .execute(&[command(OpCode::Invalid(Invalid::OpInvalidOpcode))])
        .unwrap_err();
    assert_eq!(
        err,
        ScriptError::InvalidOpcode(Invalid::OpInvalidOpcode.byte())
    );
}
