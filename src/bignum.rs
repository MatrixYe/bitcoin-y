/// @Name: bignum
///
/// @Date: 2026/5/15 17:35
///
/// @Author: Matrix.Ye
///
/// @Description: null
use num_bigint::{BigInt, Sign};
use num_traits::{Signed, Zero};


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BigNum(BigInt);

impl BigNum {
    /// 将 Bitcoin 风格的小端有符号字节流转换成 BigNum。
    ///
    /// 这里的小端字节不是二进制补码，而是“符号-绝对值”格式：
    /// 绝对值按小端序存储，最后一个字节的最高位表示符号。
    ///
    /// eg:
    /// - `[]` -> `0`
    /// - `[0x01]` -> `00000001` -> `1`
    /// - `[0x81]` -> `10000001` -> `-1`
    /// - `[0x80]` -> `10000000` -> `-0`
    /// - `[0x80,0x80]` -> `10000000 10000000` -> `-128`
    /// - `[0x80,0x00]` -> `10000000 00000000` -> `128`
    pub fn from_bytes_le(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return BigNum::zero();
        }

        let mut bytes = bytes.to_vec();
        let last_index = bytes.len() - 1;
        let negative = h_bit(bytes[last_index]);
        bytes[last_index] &= 0x7f;

        let value = BigInt::from_bytes_le(Sign::Plus, &bytes);
        match negative {
            true => BigNum(-value),
            false => BigNum(value)
        }
    }

    /// 把 BigNum 转换成 Bitcoin ScriptNum 字节。
    ///
    /// 输出采用规范编码：
    /// - `0` 编码为空向量 `[]`
    /// - 绝对值按小端序写入
    /// - 最高有效字节的最高位作为符号位
    /// - 正数如果最高有效字节已经占用 `0x80`，追加 `0x00`
    /// - 负数如果最高有效字节已经占用 `0x80`，追加 `0x80`，否则设置该字节的 `0x80`
    pub fn to_bytes_le(&self) -> Vec<u8> {
        if self.is_zero() {
            return Vec::new();
        }
        let is_negative = self.is_negative();
        let (_, mut bytes) = self.0.abs().to_bytes_le();
        let last_index = bytes.len() - 1;
        let last_byte = &mut bytes[last_index];
        let has_sign = h_bit(*last_byte);

        match (is_negative, has_sign) {
            // 是负数，有符号标识
            (true, true) => bytes.push(0x80),
            // 是负数，没有符号标识
            (true, false) => *last_byte |= 0x80,
            // 是正数，有符号标识
            (false, true) => bytes.push(0x00),
            // 是正数，没有符号标识
            (false, false) => {}
        }
        bytes
    }

    // 是否为0
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    // 是否为负数
    pub fn is_negative(&self) -> bool {
        self.0.is_negative()
    }

    // 获取绝对值
    pub fn abs(&self) -> BigInt {
        self.0.abs()
    }

    // 设置为0
    pub fn zero() -> Self {
        BigNum(BigInt::zero())
    }
}

// 单字节的最高bit位是否不为0（有符号）
fn h_bit(x: u8) -> bool {
    x & 0x80 != 0
}

impl Default for BigNum {
    fn default() -> Self {
        Self::zero()
    }
}
