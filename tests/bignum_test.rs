/// @Name: bignum_test
///
/// @Date: 2026/5/19 16:49
///
/// @Author: Matrix.Ye
///
/// @Description: null

use bitcoin_y::bignum::BigNum;


// 测试0
#[test]
fn test_bn_zero() {
    let zero = BigNum::from_bytes_le(&[]);
    assert!(zero.is_zero());
    assert_eq!(zero.to_bytes_le(), Vec::<u8>::new());
    assert_eq!(BigNum::zero(), zero);
}

//测试正数
#[test]
fn test_bn_positive_values_round_trip() {
    let cases = [
        vec![0x01],
        vec![0x7f],
        vec![0x80, 0x00],
        vec![0x00, 0x01],
        vec![0x70, 0x70],
    ];

    for bytes in cases {
        let n = BigNum::from_bytes_le(&bytes);
        assert_eq!(n.to_bytes_le(), bytes);
    }
}

// 测试负数
#[test]
fn test_bn_negative_values_round_trip() {
    let cases = [
        vec![0x81],
        vec![0xff],
        vec![0x80, 0x80],
        vec![0x00, 0x81],
    ];

    for bytes in cases {
        let n = BigNum::from_bytes_le(&bytes);
        assert_eq!(n.to_bytes_le(), bytes);
    }
}

// 测试正0 和 负0
#[test]
fn script_num_conversion_normalizes_non_minimal_zero() {
    let negative_zero = BigNum::from_bytes_le(&[0x80]);
    let padded_zero = BigNum::from_bytes_le(&[0x00, 0x00]);

    assert!(negative_zero.is_zero());
    assert!(padded_zero.is_zero());
    assert_eq!(negative_zero.to_bytes_le(), Vec::<u8>::new());
    assert_eq!(padded_zero.to_bytes_le(), Vec::<u8>::new());
}

//测试0,所有的0
#[test]
fn test_bytes_to_bignum() {
    let cases = [
        vec![0x00],
        vec![0x80],
        vec![0x00, 0x00],
        vec![0x00, 0x80],
    ];
    let zeros: Vec<_> = cases.into_iter().map(|bytes| { BigNum::from_bytes_le(bytes.as_slice()) }).collect();

    for bn in zeros {
        assert!(bn.is_zero());
    }
}
