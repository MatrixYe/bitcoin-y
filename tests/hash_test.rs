/// @Name: util_test
///
/// @Date: 2026/4/16
///
/// @Author: Matrix.Ye
///
/// @Description: 测试 utils 中的哈希函数

use bitcoin_y::utils::{double_sha256, ripemd160, sha256, sha256_and_ripemd160};

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA256 空字符串
    #[test]
    fn test_sha256_empty() {
        let result = sha256(b"");
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(hex::encode(result), expected);
    }

    /// SHA256 "abc"
    #[test]
    fn test_sha256_abc() {
        let result = sha256(b"abc");
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(hex::encode(result), expected);
    }

    /// RIPEMD160 空字符串
    #[test]
    fn test_ripemd160_empty() {
        let result = ripemd160(b"");
        let expected = "9c1185a5c5e9fc54612808977ee8f548b2258d31";
        assert_eq!(hex::encode(result), expected);
    }

    /// RIPEMD160 "abc"
    #[test]
    fn test_ripemd160_abc() {
        let result = ripemd160(b"abc");
        let expected = "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc";
        assert_eq!(hex::encode(result), expected);
    }

    /// 双重 SHA256 空字符串
    #[test]
    fn test_double_sha256_empty() {
        let result = double_sha256(b"");
        let expected = "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456";
        assert_eq!(hex::encode(result), expected);
    }

    /// 双重 SHA256 "abc"
    #[test]
    fn test_double_sha256_abc() {
        let result = double_sha256(b"abc");
        let expected = "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358";
        assert_eq!(hex::encode(result), expected);
    }

    /// SHA256+RIPEMD160 组合哈希 "abc"
    #[test]
    fn test_sha256_and_ripemd160_abc() {
        let result = sha256_and_ripemd160(b"abc");
        let expected = "bb1be98c142444d7a56aa3981c3942a978e4dc33";
        assert_eq!(hex::encode(result), expected);
    }

    /// 验证 sha256_and_ripemd160 等价于先 sha256 再 ripemd160
    #[test]
    fn test_sha256_and_ripemd160_consistency() {
        let data = b"hello bitcoin";
        let combined = sha256_and_ripemd160(data);
        let step_by_step = ripemd160(&sha256(data));
        assert_eq!(combined, step_by_step);
    }

    /// 验证 double_sha256 等价于对 sha256 结果再 sha256
    #[test]
    fn test_double_sha256_consistency() {
        let data = b"hello bitcoin";
        let combined = double_sha256(data);
        let step_by_step = sha256(&sha256(data));
        assert_eq!(combined, step_by_step);
    }
}
