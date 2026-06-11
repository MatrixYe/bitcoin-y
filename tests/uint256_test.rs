// @Name: uint256_test
// @Date: 2026/4/16 03:15
// @Author: Matrix.Ye
// @Description: Uint256 单元测试

use bitcoin_y::uint256::{Uint256, Uint256Error};

// 测试uint256的产量
#[test]
fn test_uint256_constants() {
    assert!(Uint256::ZERO.is_zero());
    assert_eq!(Uint256::ONE.to_hex(), format!("{:0>64}", "1"));
    assert_eq!(Uint256::MAX.to_hex(), "f".repeat(64));
}

// 测试低
#[test]
fn test_uint256_from_to_primitives_and_words() {
    let n = Uint256::from_u64(0x1234_5678_90ab_cdef);
    assert_eq!(n.get_low64(), 0x1234_5678_90ab_cdef);
    assert_eq!(n.to_words(), [0x90ab_cdef, 0x1234_5678, 0, 0, 0, 0, 0, 0]);

    let words = [1, 2, 3, 4, 5, 6, 7, 8];
    assert_eq!(Uint256::from_words(words).to_words(), words);
}

#[test]
fn test_uint256_from_to_bytes_round_trip() {
    let original =
        Uint256::from_hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap();
    let bytes = original.to_bytes();
    assert_eq!(Uint256::from_bytes(bytes), original);
}

#[test]
fn test_uint256_hex_and_display() {
    let cases = [
        ("", Uint256::ZERO),
        ("0", Uint256::ZERO),
        ("0x01", Uint256::ONE),
        ("1234567890abcdef", Uint256::from_u64(0x1234_5678_90ab_cdef)),
    ];

    for (hex, expected) in cases {
        assert_eq!(Uint256::from_hex(hex), Ok(expected));
    }

    let full = "0000000000000000000000000000000000000000000000001234567890abcdef";
    let n = Uint256::from_hex(full).unwrap();
    assert_eq!(n.to_hex(), full);
    assert_eq!(n.to_hex_string(true), format!("0x{full}"));
    assert_eq!(n.to_string(), full);
    assert_eq!(Uint256::from_hex_string(full), Ok(n));
}

#[test]
fn test_uint256_invalid_hex() {
    assert!(matches!(
        Uint256::from_hex("zz"),
        Err(Uint256Error::InvalidHex(_))
    ));
    assert!(matches!(
        Uint256::from_hex(&"1".repeat(65)),
        Err(Uint256Error::InvalidHex(_))
    ));
}

#[test]
fn test_uint256_comparison() {
    assert!(Uint256::from_u32(1) < Uint256::from_u32(2));
    assert!(Uint256::from_words([0, 0, 1, 0, 0, 0, 0, 0]) > Uint256::from_u64(u64::MAX));
    assert_eq!(Uint256::from_u32(1), Uint256::ONE);
    assert_ne!(Uint256::from_u32(2), Uint256::ONE);
}

#[test]
fn test_uint256_wrapping_add_and_sub() {
    assert_eq!(
        Uint256::from_u32(100) + Uint256::from_u32(200),
        Uint256::from_u32(300)
    );

    let carry = Uint256::from_u64(u64::MAX) + 1u64;
    assert_eq!(carry.to_words()[0], 0);
    assert_eq!(carry.to_words()[1], 0);
    assert_eq!(carry.to_words()[2], 1);

    assert_eq!(Uint256::ZERO - Uint256::ONE, Uint256::MAX);
    assert_eq!(Uint256::MAX + Uint256::ONE, Uint256::ZERO);
}

#[test]
fn test_uint256_bit_logic() {
    let left = Uint256::from_words([0xffff_0000, 0x1234_5678, 0, 0, 0, 0, 0, 0xaaaa_aaaa]);
    let right = Uint256::from_words([0x00ff_00ff, 0xffff_0000, 0, 0, 0, 0, 0, 0x5555_5555]);

    assert_eq!((left & right).to_words()[0], 0x00ff_0000);
    assert_eq!((left | right).to_words()[1], 0xffff_5678);
    assert_eq!((left ^ right).to_words()[7], 0xffff_ffff);
}

#[test]
fn test_uint256_shifts() {
    assert_eq!(Uint256::ONE << 0, Uint256::ONE);
    assert_eq!((Uint256::ONE << 32).to_words()[1], 1);
    assert_eq!((Uint256::ONE << 255).to_words()[7], 0x8000_0000);
    assert_eq!(Uint256::ONE << 256, Uint256::ZERO);

    let high = Uint256::from_words([0, 0, 0, 0, 0, 0, 0, 0x8000_0000]);
    assert_eq!(high >> 255, Uint256::ONE);
    assert_eq!(high >> 256, Uint256::ZERO);
}

#[test]
fn test_uint256_bits_and_low64() {
    let cases = [
        (Uint256::ZERO, 0),
        (Uint256::ONE, 1),
        (Uint256::from_u32(0x8000_0000), 32),
        (Uint256::from_u64(0x1_0000_0000), 33),
        (Uint256::MAX, 256),
    ];

    for (value, bits) in cases {
        assert_eq!(value.bits(), bits);
    }
}

#[test]
fn test_uint256_compact() {
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
        // (0x1d00ffff, "")
    ];

    for (compact, hex) in cases {
        let (target, negative, overflow) = Uint256::set_compact(compact);
        assert!(!negative);
        assert!(!overflow);
        assert_eq!(target, Uint256::from_hex(hex).unwrap());
        assert_eq!(target.get_compact(false), compact);
    }
}

#[test]
fn test_uint256_compact_sign_bit_adjusts_size() {
    let target =
        Uint256::from_hex("0000000000000000000000000000000000000000000000000000000000800000")
            .unwrap();
    assert_eq!(target.get_compact(false), 0x04008000);
}

#[test]
fn test_uint256_hash256_conversion_uses_raw_little_endian_bytes() {
    let bytes = [0x11u8; 32];
    let hash = Uint256::from(bytes);
    let n = Uint256::from(hash);
    assert_eq!(Uint256::from(n), hash);
    assert_eq!(n.to_bytes(), bytes);
}

#[test]
fn test_nbit() {
    let compact = 0x1d00ffff;
    let (target, _, _) = Uint256::set_compact(compact);
    let s = target.to_hex();
    let s2 = target.to_bytes();
    println!("s={}, s2={:?}", s, s2);
}
