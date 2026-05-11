use bitcoin_y::script::opcode::{
    BitLogic, Crypto, Expansion, Invalid, OpCode, PushValue, Stack,
};

#[test]
fn grouped_opcodes_expose_byte_and_name() {
    assert_eq!(PushValue::Op0.byte(), 0x00);
    assert_eq!(PushValue::Op0.as_str(), "OP_0");
    assert_eq!(PushValue::Op0.to_string(), "OP_0");

    assert_eq!(Stack::OpDup.byte(), 0x76);
    assert_eq!(Stack::OpDup.as_str(), "OP_DUP");

    assert_eq!(Crypto::OpHash160.byte(), 0xa9);
    assert_eq!(Crypto::OpHash160.as_str(), "OP_HASH160");

    assert_eq!(BitLogic::OpEqualVerify.byte(), 0x88);
    assert_eq!(BitLogic::OpEqualVerify.as_str(), "OP_EQUALVERIFY");
}

#[test]
fn grouped_opcodes_parse_from_named_opcode_bytes() {
    assert_eq!(PushValue::from_byte(0x00), Some(PushValue::Op0));
    assert_eq!(PushValue::from_byte(0x4c), Some(PushValue::PushData1));
    assert_eq!(Stack::from_byte(0x76), Some(Stack::OpDup));
    assert_eq!(Crypto::from_byte(0xac), Some(Crypto::OpCheckSig));
    assert_eq!(Invalid::from_byte(0xff), Some(Invalid::OpInvalidOpcode));
}

#[test]
fn top_level_opcode_preserves_group_when_parsing() {
    assert_eq!(OpCode::from_byte(0x00), Some(OpCode::Push(PushValue::Op0)));
    assert_eq!(OpCode::from_byte(0x76), Some(OpCode::Stack(Stack::OpDup)));
    assert_eq!(
        OpCode::from_byte(0xa9),
        Some(OpCode::Crypto(Crypto::OpHash160))
    );
    assert_eq!(
        OpCode::from_byte(0xb1),
        Some(OpCode::Expansion(Expansion::OpNop2))
    );
    assert_eq!(
        OpCode::from_byte(0xff),
        Some(OpCode::Invalid(Invalid::OpInvalidOpcode))
    );
}

#[test]
fn aliases_share_the_canonical_opcode_value() {
    assert_eq!(PushValue::OpFalse, PushValue::Op0);
    assert_eq!(PushValue::OpTrue, PushValue::Op1);
    assert_eq!(PushValue::OpFalse.byte(), 0x00);
    assert_eq!(PushValue::OpTrue.byte(), 0x51);

    assert_eq!(Expansion::OpCheckLockTimeVerify, Expansion::OpNop2);
    assert_eq!(Expansion::OpCheckSequenceVerify, Expansion::OpNop3);
    assert_eq!(Expansion::OpCheckLockTimeVerify.byte(), 0xb1);
    assert_eq!(Expansion::OpCheckSequenceVerify.byte(), 0xb2);
}

#[test]
fn aliases_display_as_their_canonical_opcode_name() {
    assert_eq!(PushValue::OpFalse.as_str(), "OP_0");
    assert_eq!(PushValue::OpTrue.as_str(), "OP_1");
    assert_eq!(Expansion::OpCheckLockTimeVerify.as_str(), "OP_NOP2");
    assert_eq!(Expansion::OpCheckSequenceVerify.as_str(), "OP_NOP3");
}

#[test]
fn direct_push_length_bytes_are_not_named_opcodes() {
    assert_eq!(OpCode::from_byte(0x01), None);
    assert_eq!(OpCode::from_byte(0x4b), None);
}

#[test]
fn top_level_opcode_converts_back_to_byte_and_name() {
    let opcode = OpCode::Crypto(Crypto::OpCheckSig);

    assert_eq!(opcode.byte(), 0xac);
    assert_eq!(opcode.as_str(), "OP_CHECKSIG");
    assert_eq!(opcode.to_string(), "OP_CHECKSIG");
}
