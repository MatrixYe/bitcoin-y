use bitcoin_y::script::opcode::{
    BitLogicOp, CryptoOp, ExpansionOp, InvalidOp, OpCode, PushOp, StackOp,
};

#[test]
fn grouped_opcodes_expose_byte_and_name() {
    assert_eq!(PushOp::Op0.byte(), 0x00);
    assert_eq!(PushOp::Op0.as_str(), "OP_0");
    assert_eq!(PushOp::Op0.to_string(), "OP_0");

    assert_eq!(StackOp::Dup.byte(), 0x76);
    assert_eq!(StackOp::Dup.as_str(), "OP_DUP");

    assert_eq!(CryptoOp::Hash160.byte(), 0xa9);
    assert_eq!(CryptoOp::Hash160.as_str(), "OP_HASH160");

    assert_eq!(BitLogicOp::EqualVerify.byte(), 0x88);
    assert_eq!(BitLogicOp::EqualVerify.as_str(), "OP_EQUALVERIFY");
}

#[test]
fn grouped_opcodes_parse_from_named_opcode_bytes() {
    assert_eq!(PushOp::from_byte(0x00), Some(PushOp::Op0));
    assert_eq!(PushOp::from_byte(0x4c), Some(PushOp::PushData1));
    assert_eq!(StackOp::from_byte(0x76), Some(StackOp::Dup));
    assert_eq!(CryptoOp::from_byte(0xac), Some(CryptoOp::CheckSig));
    assert_eq!(InvalidOp::from_byte(0xff), Some(InvalidOp::InvalidOpcode));
}

#[test]
fn top_level_opcode_preserves_group_when_parsing() {
    assert_eq!(OpCode::from_byte(0x00), Some(OpCode::Push(PushOp::Op0)));
    assert_eq!(OpCode::from_byte(0x76), Some(OpCode::Stack(StackOp::Dup)));
    assert_eq!(
        OpCode::from_byte(0xa9),
        Some(OpCode::Crypto(CryptoOp::Hash160))
    );
    assert_eq!(
        OpCode::from_byte(0xb1),
        Some(OpCode::Expansion(ExpansionOp::Nop2))
    );
    assert_eq!(
        OpCode::from_byte(0xff),
        Some(OpCode::Invalid(InvalidOp::InvalidOpcode))
    );
}

#[test]
fn aliases_share_the_canonical_opcode_value() {
    assert_eq!(PushOp::OpFalse, PushOp::Op0);
    assert_eq!(PushOp::OpTrue, PushOp::Op1);
    assert_eq!(PushOp::OpFalse.byte(), 0x00);
    assert_eq!(PushOp::OpTrue.byte(), 0x51);

    assert_eq!(ExpansionOp::CheckLockTimeVerify, ExpansionOp::Nop2);
    assert_eq!(ExpansionOp::CheckSequenceVerify, ExpansionOp::Nop3);
    assert_eq!(ExpansionOp::CheckLockTimeVerify.byte(), 0xb1);
    assert_eq!(ExpansionOp::CheckSequenceVerify.byte(), 0xb2);
}

#[test]
fn aliases_display_as_their_canonical_opcode_name() {
    assert_eq!(PushOp::OpFalse.as_str(), "OP_0");
    assert_eq!(PushOp::OpTrue.as_str(), "OP_1");
    assert_eq!(ExpansionOp::CheckLockTimeVerify.as_str(), "OP_NOP2");
    assert_eq!(ExpansionOp::CheckSequenceVerify.as_str(), "OP_NOP3");
}

#[test]
fn direct_push_length_bytes_are_not_named_opcodes() {
    assert_eq!(OpCode::from_byte(0x01), None);
    assert_eq!(OpCode::from_byte(0x4b), None);
}

#[test]
fn top_level_opcode_converts_back_to_byte_and_name() {
    let opcode = OpCode::Crypto(CryptoOp::CheckSig);

    assert_eq!(opcode.byte(), 0xac);
    assert_eq!(opcode.as_str(), "OP_CHECKSIG");
    assert_eq!(opcode.to_string(), "OP_CHECKSIG");
}
