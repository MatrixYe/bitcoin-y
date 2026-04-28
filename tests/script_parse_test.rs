use bitcoin_y::script::ScriptError;
use bitcoin_y::script::opcode::{BitLogicOp, CryptoOp, OpCode, PushOp, StackOp};
use bitcoin_y::script::parser::{Instruction, PushBytesKind, decode, encode};

fn assert_roundtrip(script: &[u8]) {
    let instructions = decode(script).expect("script should decode");
    let encoded = encode(&instructions).expect("instructions should encode");
    assert_eq!(encoded, script);
}

#[test]
fn decode_empty_script_returns_empty_instruction_list() {
    let instructions = decode(&[]).expect("empty script should decode");

    assert!(instructions.is_empty());
}

#[test]
fn decode_standard_p2pkh_script_pubkey() {
    let pubkey_hash = [0x11; 20];
    let mut script = vec![StackOp::Dup.byte(), CryptoOp::Hash160.byte(), 20];
    script.extend_from_slice(&pubkey_hash);
    script.extend_from_slice(&[BitLogicOp::EqualVerify.byte(), CryptoOp::CheckSig.byte()]);

    let instructions = decode(&script).expect("P2PKH script should decode");

    assert_eq!(
        instructions,
        vec![
            Instruction::Op(OpCode::Stack(StackOp::Dup)),
            Instruction::Op(OpCode::Crypto(CryptoOp::Hash160)),
            Instruction::PushBytes {
                kind: PushBytesKind::Direct(20),
                data: pubkey_hash.to_vec(),
            },
            Instruction::Op(OpCode::BitLogic(BitLogicOp::EqualVerify)),
            Instruction::Op(OpCode::Crypto(CryptoOp::CheckSig)),
        ]
    );
}

#[test]
fn decode_op0_as_named_opcode_not_push_bytes() {
    let instructions = decode(&[PushOp::Op0.byte()]).expect("OP_0 should decode");

    assert_eq!(
        instructions,
        vec![Instruction::Op(OpCode::Push(PushOp::Op0))]
    );
}

#[test]
fn decode_direct_push_reads_length_from_opcode_byte() {
    let script = [3, 0xaa, 0xbb, 0xcc];

    let instructions = decode(&script).expect("direct push should decode");

    assert_eq!(
        instructions,
        vec![Instruction::PushBytes {
            kind: PushBytesKind::Direct(3),
            data: vec![0xaa, 0xbb, 0xcc],
        }]
    );
}

#[test]
fn decode_pushdata_variants_read_little_endian_lengths() {
    let script = [
        PushOp::PushData1.byte(),
        2,
        0x01,
        0x02,
        PushOp::PushData2.byte(),
        2,
        0,
        0x03,
        0x04,
        PushOp::PushData4.byte(),
        2,
        0,
        0,
        0,
        0x05,
        0x06,
    ];

    let instructions = decode(&script).expect("pushdata script should decode");

    assert_eq!(
        instructions,
        vec![
            Instruction::PushBytes {
                kind: PushBytesKind::PushData1,
                data: vec![0x01, 0x02],
            },
            Instruction::PushBytes {
                kind: PushBytesKind::PushData2,
                data: vec![0x03, 0x04],
            },
            Instruction::PushBytes {
                kind: PushBytesKind::PushData4,
                data: vec![0x05, 0x06],
            },
        ]
    );
}

#[test]
fn decode_returns_error_when_push_payload_is_truncated() {
    let err = decode(&[3, 0xaa, 0xbb]).expect_err("payload is shorter than declared");

    assert_eq!(err, ScriptError::UnexpectedEndOfScript);
}

#[test]
fn decode_returns_error_when_pushdata_length_field_is_truncated() {
    let err = decode(&[PushOp::PushData2.byte(), 1]).expect_err("PUSHDATA2 needs two length bytes");

    assert_eq!(err, ScriptError::UnexpectedEndOfScript);
}

#[test]
fn encode_preserves_selected_push_encoding() {
    let instructions = vec![
        Instruction::PushBytes {
            kind: PushBytesKind::PushData1,
            data: vec![0xaa],
        },
        Instruction::PushBytes {
            kind: PushBytesKind::PushData2,
            data: vec![0xbb],
        },
        Instruction::PushBytes {
            kind: PushBytesKind::PushData4,
            data: vec![0xcc],
        },
    ];

    let script = encode(&instructions).expect("instructions should encode");

    assert_eq!(
        script,
        vec![
            PushOp::PushData1.byte(),
            1,
            0xaa,
            PushOp::PushData2.byte(),
            1,
            0,
            0xbb,
            PushOp::PushData4.byte(),
            1,
            0,
            0,
            0,
            0xcc,
        ]
    );
}

#[test]
fn encode_decode_roundtrip_preserves_original_script_bytes() {
    assert_roundtrip(&[
        PushOp::Op0.byte(),
        2,
        0xaa,
        0xbb,
        PushOp::PushData1.byte(),
        1,
        0xcc,
        StackOp::Dup.byte(),
    ]);
}

#[test]
fn encode_rejects_direct_push_when_length_does_not_match() {
    let err = encode(&[Instruction::PushBytes {
        kind: PushBytesKind::Direct(2),
        data: vec![0xaa],
    }])
    .expect_err("direct push length must match data length");

    assert_eq!(
        err,
        ScriptError::PushDataLengthMismatch {
            kind: "Direct",
            expected: 2,
            actual: 1,
        }
    );
}

#[test]
fn encode_rejects_invalid_direct_push_length_byte() {
    let err = encode(&[Instruction::PushBytes {
        kind: PushBytesKind::Direct(0),
        data: Vec::new(),
    }])
    .expect_err("Direct(0) is represented by OP_0 in this parser design");

    assert_eq!(err, ScriptError::InvalidPushDataDirect { actual: 0 });
}

#[test]
fn encode_rejects_pushdata1_payload_that_is_too_large() {
    let err = encode(&[Instruction::PushBytes {
        kind: PushBytesKind::PushData1,
        data: vec![0; 256],
    }])
    .expect_err("PUSHDATA1 can encode at most 255 bytes");

    assert_eq!(
        err,
        ScriptError::PushDataLengthTooLarge {
            kind: "PushData1",
            max: 255,
            actual: 256,
        }
    );
}
