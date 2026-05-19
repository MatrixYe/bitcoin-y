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
        if negative {
            BigNum(-value)
        } else {
            BigNum(value)
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

        // number是否是负数
        let is_negative = self.0.is_negative();

        // 获取 bignum 的绝对值小端字节流
        let (_, mut bytes) = self.0.abs().to_bytes_le();
        // 最高位索引
        let last_index = bytes.len() - 1;

        if is_negative {
            if h_bit(bytes[last_index]) {
                bytes.push(0x80);
            } else {
                bytes[last_index] |= 0x80;
            }
        } else {
            // 正整数
            if h_bit(bytes[last_index]) {
                bytes.push(0x00);
            }
        }
        bytes
    }

    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    pub fn zero() -> Self {
        BigNum(BigInt::zero())
    }
}

fn h_bit(x: u8) -> bool {
    x & 0x80 != 0
}

impl Default for BigNum {
    fn default() -> Self {
        Self::zero()
    }
}
