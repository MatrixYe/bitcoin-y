use bitcoin_y::bignum::BigNum;
use bitcoin_y::script::builder::ScriptBuilder;
use bitcoin_y::script::error::ScriptError;
use bitcoin_y::script::opcode::{Crypto, OpCode};

#[test]
fn push_bytes_uses_the_shortest_length_encoding() {
    let cases = [
        (vec![], vec![0x00]),
        (vec![0x11], vec![0x01, 0x11]),
        (vec![0x22; 75], [vec![0x4b], vec![0x22; 75]].concat()),
        (vec![0x33; 76], [vec![0x4c, 0x4c], vec![0x33; 76]].concat()),
        (
            vec![0x44; 256],
            [vec![0x4d, 0x00, 0x01], vec![0x44; 256]].concat(),
        ),
    ];

    for (data, expected) in cases {
        let mut builder = ScriptBuilder::new();
        builder.push_bytes(&data).unwrap();
        assert_eq!(builder.into_script().unwrap(), expected);
    }
}

#[test]
fn push_script_num_uses_script_number_bytes() {
    let mut builder = ScriptBuilder::new();
    builder
        .push_script_num(&BigNum::zero())
        .unwrap()
        .push_script_num(&BigNum::from_i32(-1))
        .unwrap()
        .push_script_num(&BigNum::from_i32(128))
        .unwrap();

    assert_eq!(
        builder.into_script().unwrap(),
        vec![0x00, 0x01, 0x81, 0x02, 0x80, 0x00]
    );
}

#[test]
fn builds_early_coinbase_p2pk_script() {
    let public_key = [0x02; 65];
    let mut builder = ScriptBuilder::new();
    builder
        .push_bytes(&public_key)
        .unwrap()
        .push_opcode(OpCode::Crypto(Crypto::OpCheckSig))
        .unwrap();

    let script = builder.into_script().unwrap();
    assert_eq!(script[0], 65);
    assert_eq!(&script[1..66], &public_key);
    assert_eq!(script[66], Crypto::OpCheckSig.byte());
}

#[test]
fn push_str_encodes_utf8_bytes() {
    let mut builder = ScriptBuilder::new();
    builder.push_str("比特币").unwrap();

    let bytes = "比特币".as_bytes();
    let mut expected = vec![bytes.len() as u8];
    expected.extend_from_slice(bytes);
    assert_eq!(builder.into_script().unwrap(), expected);
}

#[test]
fn failed_push_does_not_modify_the_builder() {
    let mut builder = ScriptBuilder::new();
    let error = builder.push_bytes(&vec![0; 10_000]).unwrap_err();

    assert_eq!(
        error,
        ScriptError::ScriptTooLarge {
            max: 10_000,
            actual: 10_003,
        }
    );
    assert_eq!(builder.into_script().unwrap(), Vec::<u8>::new());
}
