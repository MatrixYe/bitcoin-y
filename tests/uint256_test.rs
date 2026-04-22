// @Name: uint256_test
// @Date: 2026/4/16 03:15
// @Author: Matrix.Ye
// @Description: null

#[cfg(test)]
mod tests {
    use bitcoin_y::uint256::Uint256;

    #[test]
    fn test_conversion() {
        // 测试 to_bytes 和 from_bytes
        let original = Uint256::from(0x1234567890abcdefu64);
        let bytes = original.to_bytes();
        let restored = Uint256::from_bytes(bytes);
        assert_eq!(original, restored);

        // 测试十六进制转换
        let hex_str = "0000000000000000000000000000000000000000000000001234567890abcdef";
        let from_hex = Uint256::from_hex_string(hex_str).unwrap();
        assert_eq!(from_hex.to_hex_string(false), hex_str);

        // 测试带前缀的十六进制
        let hex_str_with_prefix =
            "0x0000000000000000000000000000000000000000000000001234567890abcdef";
        let from_hex_prefix = Uint256::from_hex_string(hex_str_with_prefix).unwrap();
        assert_eq!(from_hex_prefix, from_hex);
    }

    #[test]
    fn test_arithmetic() {
        // 测试加法
        let a = Uint256::from(100u64);
        let b = Uint256::from(200u64);
        let c = a + b;
        assert_eq!(c, Uint256::from(300u64));

        // 测试减法
        let d = c - a;
        assert_eq!(d, b);

        // 测试乘法
        let e = a * 5;
        assert_eq!(e, Uint256::from(500u64));
    }

    #[test]
    fn test_comparison() {
        let a = Uint256::from(100u64);
        let b = Uint256::from(200u64);
        let c = Uint256::from(100u64);

        assert!(a < b);
        assert!(b > a);
        assert_eq!(a, c);
        assert!(a <= c);
        assert!(c >= a);
    }

    #[test]
    fn test_bits() {
        // 测试 bits() 方法
        let a = Uint256::from(0u64);
        assert_eq!(a.bits(), 0);

        let b = Uint256::from(1u64);
        assert_eq!(b.bits(), 1);

        let c = Uint256::from(0x80000000u64);
        assert_eq!(c.bits(), 32);

        let d = Uint256::from(0x100000000u64);
        assert_eq!(d.bits(), 33);
    }

    #[test]
    fn test_compact() {
        // 测试 nBits 转换
        let test_cases = vec![
            // (nBits, expected_hex)
            // (
            //     0x1d00ffff,
            //     "0x00000000FFFF0000000000000000000000000000000000000000000000000000",
            // ),
            (
                0x1b0404cb,
                "0x00000000000404CB000000000000000000000000000000000000000000000000",
            ),
            (
                0x20123456,
                "0x1234560000000000000000000000000000000000000000000000000000000000",
            ),
        ];

        for (n_bits, expected_hex) in test_cases {
            // 测试 set_compact
            let (target, negative, overflow) = Uint256::set_compact(n_bits);
            assert!(!negative, "Should not be negative");
            assert!(!overflow, "Should not overflow");
            assert_eq!(
                target,
                Uint256::from_hex_string(expected_hex).unwrap(),
                "Target value should match"
            );
            // assert_eq!(target.to_hex_string(true), expected_hex);
            // 测试 get_compact
            let compact = target.get_compact(false);
            assert_eq!(compact, n_bits, "Compact value should match");
        }
    }

    #[test]
    fn test_is_zero() {
        let zero = Uint256::default();
        assert!(zero.is_zero());

        let non_zero = Uint256::from(1u64);
        assert!(!non_zero.is_zero());
    }

    #[test]
    fn test_get_low64() {
        let a = Uint256::from(0x1234567890abcdefu64);
        assert_eq!(a.get_low64(), 0x1234567890abcdefu64);

        let b = Uint256::from(0x1111111122222222u64);
        assert_eq!(b.get_low64(), 0x1111111122222222u64);
    }
}
