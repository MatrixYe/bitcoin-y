use bitcoin_y::bignum::BigNum;
use bitcoin_y::block::{Block, BlockHeader};
use bitcoin_y::uint256::Uint256;

#[test]
fn bignum_set_compact_matches_known_targets() {
    let cases = [
        (
            0x1d00ffff,
            "00000000ffff0000000000000000000000000000000000000000000000000000",
        ),
        (
            0x1b0404cb,
            "00000000000404cb000000000000000000000000000000000000000000000000",
        ),
        (
            0x20123456,
            "1234560000000000000000000000000000000000000000000000000000000000",
        ),
    ];

    for (compact, target_hex) in cases {
        let target = BigNum::set_compact(compact);
        assert_eq!(target.to_uint256(), Uint256::from_hex(target_hex).unwrap());
        assert_eq!(target.get_compact(), compact);
    }
}

#[test]
fn bignum_compact_preserves_mpi_sign_semantics() {
    let negative_one = BigNum::set_compact(0x01810000);
    assert_eq!(negative_one, BigNum::from_i32(-1));
    assert_eq!(negative_one.get_compact(), 0x01810000);

    let positive_with_sign_byte = BigNum::from_u32(0x0080_0000);
    assert_eq!(positive_with_sign_byte.get_compact(), 0x04008000);
    assert_eq!(BigNum::set_compact(0x04008000), positive_with_sign_byte);
}

#[test]
fn bignum_and_uint256_convert_through_little_endian_bytes() {
    let value =
        Uint256::from_hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap();

    let bn = BigNum::from_uint256(value);
    assert_eq!(bn.to_uint256(), value);
    assert_eq!(BigNum::from(value).to_uint256(), value);
    assert_eq!(Uint256::from(&bn), value);
}

#[test]
fn bignum_to_uint256_matches_original_low_256_bit_semantics() {
    assert_eq!(BigNum::from_i32(-1).to_uint256(), Uint256::ONE);
    assert_eq!((BigNum::from_u32(1) << 256).to_uint256(), Uint256::ZERO);
}

#[test]
fn block_work_matches_original_formula() {
    let block = Block {
        header: BlockHeader {
            bits: 0x1d00ffff,
            ..BlockHeader::default()
        },
        vtx: vec![],
    };

    assert_eq!(block.get_work(), BigNum::from_hex("100010001").unwrap());

    let invalid_block = Block {
        header: BlockHeader {
            bits: 0x01810000,
            ..BlockHeader::default()
        },
        vtx: vec![],
    };
    assert_eq!(invalid_block.get_work(), BigNum::zero());
}
