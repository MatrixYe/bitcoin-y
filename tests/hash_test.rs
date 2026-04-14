/// @Name: hash_test
///
/// @Date: 2026/4/15 00:31
///
/// @Author: Matrix.Ye
///
/// @Description: 测试哈希函数
use bitcoin_y::utils::{double_sha256, sha256, sha256_and_ripemd160};
use hex;
#[cfg(test)]
mod test {
    use super::*;

    /// @Description: 测试单次SHA256哈希函数
    /// [标准实现对照](https://en.bitcoin.it/wiki/Protocol_documentation#Block_Headers)
    #[test]
    fn test_hash256() {
        let v = "hello";
        // assert_eq!(v, "hello");
        let hash = sha256(v.as_bytes());
        assert_eq!(hash.len(), 32);
        assert_eq!(
            hex::encode(hash),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    /// @Description: 测试双重SHA256哈希函数
    #[test]
    fn test_doublehash() {
        let v = "hello";
        // assert_eq!(v, "hello");
        let hash = double_sha256(v.as_bytes());
        assert_eq!(hash.len(), 32);
        assert_eq!(
            hex::encode(hash),
            "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50"
        );
    }

    /// @Description: 测试SHA256+RIPEMD160哈希函数
    /// [标准实现对照](https://en.bitcoin.it/wiki/Protocol_documentation#Block_Headers)
    #[test]
    fn test_sha256_and_ripemd160() {
        let v = "hello";
        let hash = sha256_and_ripemd160(v.as_bytes());
        assert_eq!(hash.len(), 20);
        assert_eq!(
            hex::encode(hash),
            "b6a9c8c230722b7c748331a8b450f05566dc7d0f"
        );
    }
}
