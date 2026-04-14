use ripemd::Ripemd160;
/// @Name: utils
///
/// @Date: 2026/4/13 21:32
///
/// @Author: Matrix.Ye
///
/// @Description: 工具函数
use sha2::{Digest, Sha256};

/// 计算 SHA256 哈希
///
/// # 参数
///
/// * `data` - 要计算哈希的数据
///
/// # 返回值
///
/// * `[u8; 32]` - SHA256 哈希结果 (32个字节)
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(data);
    hash.into()
}

///
///
/// # Arguments
///
/// * `data`: 数据
///
/// returns: [u8; 20]
///
/// # Examples
///
/// ```
///
/// ```
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let hash = Ripemd160::digest(data);
    hash.into()
}

///
///
/// # Arguments
///
/// * `data`:
///
/// returns: [u8; 20]
///
/// # Examples
///
/// ```
///
/// ```
pub fn sha256_and_ripemd160(data: &[u8]) -> [u8; 20] {
    let hash = sha256(data);
    ripemd160(&hash)
}

/// 计算双重 SHA256 哈希 (SHA256(SHA256(data)))
///
/// 比特币中使用双重 SHA256 来计算交易 ID 和区块哈希
///
/// # 参数
///
/// * `data` - 要计算哈希的数据
///
/// # 返回值
///
/// * `[u8; 32]` - 双重 SHA256 哈希结果 (32个字节)
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first_hash = Sha256::digest(data);
    let second_hash = Sha256::digest(first_hash);
    second_hash.into()
}

/// 将压缩格式的难度目标(nBits)转换为完整的256位大端目标值
/// 严格对标 Bitcoin Core 官方实现
pub fn compact_to_target(compact: u32) -> Option<[u8; 32]> {
    let exponent = (compact >> 24) as u32;
    let mut mantissa = compact & 0x00FFFFFF;

    // 官方有效性校验
    if exponent == 0 || mantissa == 0 || (mantissa & 0x800000) != 0 {
        return None;
    }
    if exponent > 32 {
        return None;
    }

    let mut target = [0u8; 32];

    // 核心逻辑：Bitcoin Core 原始公式 mantissa * 256^(exponent-3)
    if exponent <= 3 {
        // 小指数：右移填充到低位
        let shift = 8 * (3 - exponent);
        mantissa >>= shift;
        let bytes = mantissa.to_be_bytes();
        // 填充到数组最后3字节
        target[31] = bytes[3];
        if exponent >= 2 {
            target[30] = bytes[2];
        }
        if exponent == 3 {
            target[29] = bytes[1];
        }
    } else {
        // 大指数：左移填充到高位
        let start = (32 - exponent) as usize;
        target[start] = (mantissa >> 16) as u8;
        target[start + 1] = (mantissa >> 8) as u8;
        target[start + 2] = mantissa as u8;
    }

    Some(target)
}

/// 将完整的256位大端目标值压缩为nBits格式
/// 严格对标 Bitcoin Core 官方实现
/// todo 在小难度便捷测试上，存在错误，需要修复
pub fn target_to_compact(target: &[u8; 32]) -> u32 {
    if target.iter().all(|&x| x == 0) {
        return 0;
    }

    // 计算有效字节长度（从高位到低位）
    let mut first_non_zero = 0;
    while first_non_zero < 32 && target[first_non_zero] == 0 {
        first_non_zero += 1;
    }
    let mut size = 32 - first_non_zero;

    // 提取尾数
    let mut mantissa: u32 = 0;
    if size <= 3 {
        // 小数值：从低位提取（修复关键！）
        let start = 32 - size;
        for i in 0..size {
            mantissa |= (target[start + i] as u32) << (8 * (2 - i));
        }
    } else {
        // 大数值：从高位提取
        mantissa = (target[first_non_zero] as u32) << 16
            | (target[first_non_zero + 1] as u32) << 8
            | target[first_non_zero + 2] as u32;
    }

    // 官方规则：负数修正
    if (mantissa & 0x800000) != 0 {
        mantissa >>= 8;
        size += 1;
    }

    (size as u32) << 24 | (mantissa & 0x00FFFFFF)
}
