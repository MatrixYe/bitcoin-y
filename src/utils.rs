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

/// 解压缩 nBits -> 256位目标值 (Bitcoin Core arith_uint256::SetCompact)
pub fn compact_to_target(compact: u32) -> Option<[u8; 32]> {
    let size = (compact >> 24) as u32;
    let mut mantissa = compact & 0x00FFFFFF;

    // 官方校验规则
    if size == 0 || mantissa == 0 || (mantissa & 0x800000) != 0 {
        return None;
    }
    if size > 32 {
        return None;
    }

    let mut target = [0u8; 32];

    // 官方核心逻辑
    if size <= 3 {
        mantissa >>= 8 * (3 - size);
        let bytes = mantissa.to_be_bytes();
        // 小数值填充到数组末尾（最低位）
        target[31] = bytes[3];
        if size >= 2 {
            target[30] = bytes[2];
        }
        if size == 3 {
            target[29] = bytes[1];
        }
    } else {
        let start = (32 - size) as usize;
        target[start] = (mantissa >> 16) as u8;
        target[start + 1] = (mantissa >> 8) as u8;
        target[start + 2] = mantissa as u8;
    }

    Some(target)
}

/// 压缩 256位目标值 -> nBits (Bitcoin Core arith_uint256::GetCompact)
pub fn target_to_compact(target: &[u8; 32]) -> u32 {
    if target.iter().all(|&b| b == 0) {
        return 0;
    }

    // 计算有效长度
    let mut first_non_zero = 0;
    while first_non_zero < 32 && target[first_non_zero] == 0 {
        first_non_zero += 1;
    }
    let mut size = 32 - first_non_zero;
    let mut mantissa: u32 = 0;

    // ✅ 修复关键：小数值强制从数组末尾提取
    if size <= 3 {
        let start = 32 - size;
        mantissa = match size {
            1 => (target[start] as u32) << 16,
            2 => ((target[start] as u32) << 16) | ((target[start + 1] as u32) << 8),
            3 => {
                ((target[start] as u32) << 16)
                    | ((target[start + 1] as u32) << 8)
                    | target[start + 2] as u32
            }
            _ => 0,
        };
    } else {
        // 大数值从高位提取
        mantissa = ((target[first_non_zero] as u32) << 16)
            | ((target[first_non_zero + 1] as u32) << 8)
            | target[first_non_zero + 2] as u32;
    }

    // 官方负数修正
    if (mantissa & 0x800000) != 0 {
        mantissa >>= 8;
        size += 1;
    }

    (size as u32) << 24 | (mantissa & 0x00FFFFFF)
}
