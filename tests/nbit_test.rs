/// @Name: nbit_test
///
/// @Date: 2026/4/15
///
/// @Author: Matrix.Ye
///
/// @Description: 测试难度目标的压缩和解压缩函数
use bitcoin_y::utils::{compact_to_target, target_to_compact};
use hex;

/// @Description: 测试难度目标的压缩和解压缩函数
#[cfg(test)]
mod tests {
    use super::*;
    /// @Description: 测试难度目标的压缩和解压缩函数
    #[test]
    fn test_nbits() {
        let nbit = 0x1b0404cb;
        let target = compact_to_target(nbit).unwrap();

        assert_eq!(hex::encode(target).to_uppercase(), "00000000000404CB000000000000000000000000000000000000000000000000");
        let bits = target_to_compact(&target);
        assert_eq!(bits, nbit);
    }
    // 1. 创世区块基准测试
    #[test]
    fn test_genesis_block() {
        const GENESIS_BITS: u32 = 0x1D00FFFF;
        let target = compact_to_target(GENESIS_BITS).unwrap();
        let bits = target_to_compact(&target);
        assert_eq!(bits, GENESIS_BITS);
    }

    // 2. 最小有效nBits
    #[test]
    fn test_min_valid_nbits() {
        let bits = 0x0100007F;
        let target = compact_to_target(bits).unwrap();
        assert_eq!(target_to_compact(&target), bits);
    }

    // 3. 边界有效值
    #[test]
    fn test_max_exponent_valid() {
        let bits = 0x20123456;
        let target = compact_to_target(bits).unwrap();
        assert_eq!(target_to_compact(&target), bits);
    }

    #[test]
    fn test_max_valid_mantissa() {
        let bits = 0x047FFFFF;
        let target = compact_to_target(bits).unwrap();
        assert_eq!(target_to_compact(&target), bits);
    }

    //noinspection ALL
    // 4. 无效值测试
    #[test]
    fn test_invalid_nbits_zero() {
        assert!(compact_to_target(0).is_none());
    }

    #[test]
    fn test_invalid_nbits_exponent_zero() {
        assert!(compact_to_target(0x00123456).is_none());
    }

    #[test]
    fn test_invalid_nbits_mantissa_zero() {
        assert!(compact_to_target(0x05000000).is_none());
    }

    #[test]
    fn test_invalid_nbits_negative_mantissa() {
        assert!(compact_to_target(0x04800000).is_none());
    }

    #[test]
    fn test_invalid_nbits_exponent_too_large() {
        assert!(compact_to_target(0x21123456).is_none());
    }

    // 5. 全零目标
    #[test]
    fn test_zero_target_compact() {
        let zero_target = [0u8; 32];
        assert_eq!(target_to_compact(&zero_target), 0);
    }

    // 6. 小指数临界测试（全部修复）
    #[test]
    fn test_exponent_1() {
        // 0x1d00ffff
        let bits = 0x0100007F;
        let target = compact_to_target(bits).unwrap();
        assert_eq!(target_to_compact(&target), bits);
    }

    #[test]
    fn test_exponent_2() {
        let bits = 0x02007FFF;
        let target = compact_to_target(bits).unwrap();
        assert_eq!(target_to_compact(&target), bits);
    }

    #[test]
    fn test_exponent_3() {
        let bits = 0x03123456;
        let target = compact_to_target(bits).unwrap();
        assert_eq!(target_to_compact(&target), bits);
    }

    // 7. 负数自动修正
    #[test]
    fn test_auto_adjust_negative_mantissa() {
        let mut target = [0u8; 32];
        target[28] = 0x80;
        let bits = target_to_compact(&target);
        let target_back = compact_to_target(bits).unwrap();
        assert_eq!(target_to_compact(&target_back), bits);
    }

    // 8. 最大指数32
    #[test]
    fn test_exponent_32_full() {
        let bits = 0x207FFFFF;
        let target = compact_to_target(bits).unwrap();
        assert_eq!(target_to_compact(&target), bits);
    }
}
