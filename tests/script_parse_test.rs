use bitcoin_y::script::opcode::{BitLogic, Crypto, OpCode, PushValue, Stack};
use bitcoin_y::script::parser::{decode, encode, PushBytesKind, ScriptData, ScriptToken};
use bitcoin_y::script::ScriptError;

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
    let mut script = vec![Stack::OpDup.byte(), Crypto::OpHash160.byte(), 20];
    script.extend_from_slice(&pubkey_hash);
    script.extend_from_slice(&[BitLogic::OpEqualVerify.byte(), Crypto::OpCheckSig.byte()]);

    let instructions = decode(&script).expect("P2PKH script should decode");

    assert_eq!(
        instructions,
        vec![
            ScriptToken::Command(OpCode::Stack(Stack::OpDup)),
            ScriptToken::Command(OpCode::Crypto(Crypto::OpHash160)),
            ScriptToken::Data(ScriptData::Bytes {
                kind: PushBytesKind::Direct(20),
                bytes: pubkey_hash.to_vec(),
            }),
            ScriptToken::Command(OpCode::BitLogic(BitLogic::OpEqualVerify)),
            ScriptToken::Command(OpCode::Crypto(Crypto::OpCheckSig)),
        ]
    );
}

#[test]
fn decode_op0_as_small_int_data() {
    let instructions = decode(&[PushValue::Op0.byte()]).expect("OP_0 should decode");

    assert_eq!(
        instructions,
        vec![ScriptToken::Data(ScriptData::SmallInt(0))]
    );
}

#[test]
fn decode_direct_push_reads_length_from_opcode_byte() {
    let script = [3, 0xaa, 0xbb, 0xcc];

    let instructions = decode(&script).expect("direct push should decode");

    assert_eq!(
        instructions,
        vec![ScriptToken::Data(ScriptData::Bytes {
            kind: PushBytesKind::Direct(3),
            bytes: vec![0xaa, 0xbb, 0xcc],
        })]
    );
}

#[test]
fn decode_pushdata_variants_read_little_endian_lengths() {
    let script = [
        PushValue::PushData1.byte(),
        2,
        0x01,
        0x02,
        PushValue::PushData2.byte(),
        2,
        0,
        0x03,
        0x04,
        PushValue::PushData4.byte(),
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
            ScriptToken::Data(ScriptData::Bytes {
                kind: PushBytesKind::PushData1,
                bytes: vec![0x01, 0x02],
            }),
            ScriptToken::Data(ScriptData::Bytes {
                kind: PushBytesKind::PushData2,
                bytes: vec![0x03, 0x04],
            }),
            ScriptToken::Data(ScriptData::Bytes {
                kind: PushBytesKind::PushData4,
                bytes: vec![0x05, 0x06],
            }),
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
    let err = decode(&[PushValue::PushData2.byte(), 1]).expect_err("PUSHDATA2 needs two length bytes");

    assert_eq!(err, ScriptError::UnexpectedEndOfScript);
}

#[test]
fn encode_preserves_selected_push_encoding() {
    let instructions = vec![
        ScriptToken::Data(ScriptData::Bytes {
            kind: PushBytesKind::PushData1,
            bytes: vec![0xaa],
        }),
        ScriptToken::Data(ScriptData::Bytes {
            kind: PushBytesKind::PushData2,
            bytes: vec![0xbb],
        }),
        ScriptToken::Data(ScriptData::Bytes {
            kind: PushBytesKind::PushData4,
            bytes: vec![0xcc],
        }),
    ];

    let script = encode(&instructions).expect("instructions should encode");

    assert_eq!(
        script,
        vec![
            PushValue::PushData1.byte(),
            1,
            0xaa,
            PushValue::PushData2.byte(),
            1,
            0,
            0xbb,
            PushValue::PushData4.byte(),
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
        PushValue::Op0.byte(),
        2,
        0xaa,
        0xbb,
        PushValue::PushData1.byte(),
        1,
        0xcc,
        Stack::OpDup.byte(),
    ]);
}

#[test]
fn encode_rejects_direct_push_when_length_does_not_match() {
    let err = encode(&[ScriptToken::Data(ScriptData::Bytes {
        kind: PushBytesKind::Direct(2),
        bytes: vec![0xaa],
    })])
        .expect_err("direct push length must match bytes length");

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
    let err = encode(&[ScriptToken::Data(ScriptData::Bytes {
        kind: PushBytesKind::Direct(0),
        bytes: Vec::new(),
    })])
        .expect_err("Direct(0) is represented by OP_0 in this parser design");

    assert_eq!(err, ScriptError::InvalidPushDataDirect { actual: 0 });
}

#[test]
fn encode_rejects_pushdata1_payload_that_is_too_large() {
    let err = encode(&[ScriptToken::Data(ScriptData::Bytes {
        kind: PushBytesKind::PushData1,
        bytes: vec![0; 256],
    })])
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
