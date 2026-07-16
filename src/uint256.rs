//！ @Name: uint256
//！ @Date: 2026/4/14 14:52
//！ @Author: Matrix.Ye
//！ @Description: 固定 256 位无符号整数，参考 Bitcoin v0.3.19 base_uint<256>

use std::cmp::Ordering;
use std::fmt;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Shl, ShlAssign,
    Shr, ShrAssign, Sub, SubAssign,
};
use thiserror::Error;

const WIDTH: usize = 8;
const BYTE_LEN: usize = 32;
const WORD_BITS: u32 = 32;

/// 固定 256 位无符号整数。
///
/// 内部采用小端 word 序：`words[0]` 是最低有效 32 位，`words[7]` 是最高有效 32 位。
/// 这与 Bitcoin v0.3.19 的 `base_uint<256>` / `uint256` 语义一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Uint256(pub [u32; WIDTH]);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Uint256Error {
    #[error("invalid uint256 hex string: {0}")]
    InvalidHex(String),
}

impl Uint256 {
    pub const ZERO: Self = Self([0; WIDTH]);
    pub const ONE: Self = Self([1, 0, 0, 0, 0, 0, 0, 0]);
    pub const MAX: Self = Self([u32::MAX; WIDTH]);
}

impl Uint256 {
    /// 从小端 word 数组构造，`words[0]` 是最低有效 word。
    pub fn from_words(words: [u32; WIDTH]) -> Self {
        Self(words)
    }
    // const fn constant() -> String {
    //
    //     let mut s = "hello".to_string();
    //     s =s.to_uppercase();
    //     s
    // }

    pub fn from_u32(value: u32) -> Self {
        Self([value, 0, 0, 0, 0, 0, 0, 0])
    }

    pub fn from_u64(value: u64) -> Self {
        //0xaaaa_bbbb_cccc_dddd
        //[0xaaaa_bbbb,0xcccc_dddd,0,0,0,0,0,0,0]
        Self([value as u32, (value >> WORD_BITS) as u32, 0, 0, 0, 0, 0, 0])
    }

    /// 从 32 字节小端序构造。用于区块哈希、序列化字节等原始数据。
    pub fn from_bytes(bytes: [u8; BYTE_LEN]) -> Self {
        let mut words = [0u32; WIDTH];
        for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(4)) {
            *word = u32::from_le_bytes(chunk.try_into().expect("chunk size is 4"));
        }
        Self(words)
    }

    /// 从大端显示序 hex 构造。支持可选 `0x` / `0X` 前缀，最多 64 个 hex 字符。
    pub fn from_hex(hex: &str) -> Result<Self, Uint256Error> {
        let value = hex.trim(); //去除空歌
        let value = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .unwrap_or(value); //去除0x,0X

        if value.is_empty() {
            return Ok(Self::ZERO);
        }
        if value.len() > 64 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Uint256Error::InvalidHex(hex.to_string()));
        }

        let mut padded = String::with_capacity(64);
        padded.extend(std::iter::repeat_n('0', 64 - value.len()));
        padded.push_str(value);

        let mut bytes = [0u8; BYTE_LEN];
        hex::decode_to_slice(&padded, &mut bytes)
            .map_err(|_| Uint256Error::InvalidHex(hex.to_string()))?;
        bytes.reverse();
        Ok(Self::from_bytes(bytes))
    }

    /// 兼容旧 API：从大端显示序 hex 构造。
    pub fn from_hex_string(hex: &str) -> Result<Self, Uint256Error> {
        Self::from_hex(hex)
    }

    pub const fn to_words(self) -> [u32; WIDTH] {
        self.0
    }

    /// 转换为 32 字节小端序。//todo
    pub fn to_bytes(self) -> [u8; BYTE_LEN] {
        let mut bytes = [0u8; BYTE_LEN];
        for (chunk, word) in bytes.chunks_exact_mut(4).zip(self.0) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    /// 转换为 64 字符大端显示序 hex。
    pub fn to_hex(self) -> String {
        let mut bytes = self.to_bytes();
        bytes.reverse();
        hex::encode(bytes)
    }

    /// 兼容旧 API：转换为大端显示序 hex，`prefix=true` 时带 `0x`。
    pub fn to_hex_string(&self, prefix: bool) -> String {
        let hex = self.to_hex();
        match prefix {
            true => format!("0x{hex}"),
            false => hex,
        }
    }

    pub fn is_zero(self) -> bool {
        self == Self::ZERO
    }

    /// 返回最高有效位位置 + 1；0 返回 0。//todo
    pub fn bits(self) -> u32 {
        for i in (0..WIDTH).rev() {
            let word = self.0[i];
            if word != 0 {
                return i as u32 * WORD_BITS + (WORD_BITS - word.leading_zeros());
            }
        }
        0
    }

    pub fn get_low64(self) -> u64 {
        self.0[0] as u64 | ((self.0[1] as u64) << WORD_BITS)
    }

    /// 从 Bitcoin compact target / nBits 构造，返回 `(target, negative, overflow)`。
    pub fn set_compact(nbits: u32) -> (Self, bool, bool) {
        // 前8位 为指数
        let exponent = nbits >> 24;
        // 后24位 为尾数，忽略符号位
        let mantissa = nbits & 0x007f_ffff;
        // 尾数的首位为符号位置
        let sign = nbits & 0x0080_0000 != 0;

        let target = match exponent <= 3 {
            true => Self::from_u32(mantissa >> (8 * (3 - exponent))),
            false => Self::from_u32(mantissa) << (8 * (exponent - 3)),
        };

        let negative = mantissa != 0 && sign;
        let overflow = mantissa != 0
            && (exponent > 34
                || (mantissa > 0xff && exponent > 33)
                || (mantissa > 0xffff && exponent > 32));

        (target, negative, overflow)
    }

    /// 转换为 Bitcoin compact target / nBits
    pub fn get_compact(self, negative: bool) -> u32 {
        let mut n_size = self.bits().div_ceil(8);
        let mut n_compact = match n_size <= 3 {
            true => (self.get_low64() << (8 * (3 - n_size))) as u32,
            false => (self >> (8 * (n_size - 3))).get_low64() as u32,
        };

        if (n_compact & 0x0080_0000) != 0 {
            n_compact >>= 8;
            n_size += 1;
        }

        n_compact &= 0x007f_ffff;
        n_compact |= n_size << 24;
        if negative && (n_compact & 0x007f_ffff) != 0 {
            n_compact |= 0x0080_0000;
        }
        n_compact
    }

    fn wrapping_add_assign(&mut self, rhs: Self) {
        let mut carry = 0u64;
        for i in 0..WIDTH {
            let sum = self.0[i] as u64 + rhs.0[i] as u64 + carry;
            self.0[i] = sum as u32;
            carry = sum >> WORD_BITS;
        }
    }

    fn wrapping_sub_assign(&mut self, rhs: Self) {
        let mut borrow = false;
        for i in 0..WIDTH {
            let (value, borrow_rhs) = self.0[i].overflowing_sub(rhs.0[i]);
            let (value, borrow_prev) = value.overflowing_sub(u32::from(borrow));
            self.0[i] = value;
            borrow = borrow_rhs || borrow_prev;
        }
    }

    fn shl_bits_assign(&mut self, shift: u32) {
        *self = match shift >= 256 {
            true => Self::ZERO,
            false => {
                let mut result = [0u32; WIDTH];
                let word_shift = (shift / WORD_BITS) as usize;
                let bit_shift = shift % WORD_BITS;

                for (i, word) in result.iter_mut().enumerate().skip(word_shift) {
                    *word = self.0[i - word_shift] << bit_shift;
                    if bit_shift > 0 && i > word_shift {
                        *word |= self.0[i - word_shift - 1] >> (WORD_BITS - bit_shift);
                    }
                }
                Self(result)
            }
        };
    }

    fn shr_bits_assign(&mut self, shift: u32) {
        *self = match shift >= 256 {
            true => Self::ZERO,
            false => {
                let mut result = [0u32; WIDTH];
                let word_shift = (shift / WORD_BITS) as usize;
                let bit_shift = shift % WORD_BITS;

                for (i, word) in result.iter_mut().enumerate().take(WIDTH - word_shift) {
                    *word = self.0[i + word_shift] >> bit_shift;
                    if bit_shift > 0 && i + word_shift + 1 < WIDTH {
                        *word |= self.0[i + word_shift + 1] << (WORD_BITS - bit_shift);
                    }
                }
                Self(result)
            }
        };
    }
}

impl From<[u32; WIDTH]> for Uint256 {
    fn from(value: [u32; WIDTH]) -> Self {
        Self::from_words(value)
    }
}

/// 类型转换: uint256 => `[u32;8]`
impl From<Uint256> for [u32; WIDTH] {
    fn from(value: Uint256) -> Self {
        value.to_words()
    }
}

/// 类型转换: `[u8;32]` => uint256
impl From<[u8; BYTE_LEN]> for Uint256 {
    fn from(value: [u8; BYTE_LEN]) -> Self {
        Self::from_bytes(value)
    }
}

/// 类型转换: uint256 => `[u8;32]`
impl From<Uint256> for [u8; BYTE_LEN] {
    fn from(value: Uint256) -> Self {
        value.to_bytes()
    }
}
/// 类型转换: `u32` => uint256
impl From<u32> for Uint256 {
    fn from(value: u32) -> Self {
        Self::from_u32(value)
    }
}

/// 类型转换: u64 => uint256
/// ```rust
/// use bitcoin_y::uint256::Uint256;
/// let x:u64 =99u64;
/// let y:Uint256= x.into();
/// ```
impl From<u64> for Uint256 {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

/// > ,< , ==, None
impl PartialOrd for Uint256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// > ,< , ==
impl Ord for Uint256 {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..WIDTH).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => continue,
                order => return order,
            }
        }
        Ordering::Equal
    }
}

/// uint256 ==> str
impl fmt::Display for Uint256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// 算术符重载:+ uin5256
impl Add for Uint256 {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}

/// 算术符重载:+=
impl AddAssign for Uint256 {
    fn add_assign(&mut self, rhs: Self) {
        self.wrapping_add_assign(rhs);
    }
}

/// 算术符重载:+ u64
impl Add<u64> for Uint256 {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        self + Self::from_u64(rhs)
    }
}

/// 算术符重载:+= u64
impl AddAssign<u64> for Uint256 {
    fn add_assign(&mut self, rhs: u64) {
        *self += Self::from_u64(rhs);
    }
}

/// 算术符重载: -
impl Sub for Uint256 {
    type Output = Self;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self -= rhs;
        self
    }
}

/// 算术符重载:-=
impl SubAssign for Uint256 {
    fn sub_assign(&mut self, rhs: Self) {
        self.wrapping_sub_assign(rhs);
    }
}

/// 算术符重载: &
impl BitAnd for Uint256 {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        let mut words = [0u32; WIDTH];
        for (i, word) in words.iter_mut().enumerate() {
            *word = self.0[i] & rhs.0[i];
        }
        Self(words)
    }
}

/// 算术符重载: &=
impl BitAndAssign for Uint256 {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

/// 算术符重载: |
impl BitOr for Uint256 {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        let mut words = [0u32; WIDTH];
        for (i, word) in words.iter_mut().enumerate() {
            *word = self.0[i] | rhs.0[i];
        }
        Self(words)
    }
}

/// 算术符重载: |=
impl BitOrAssign for Uint256 {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

/// 算术符重载: ^
impl BitXor for Uint256 {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        let mut words = [0u32; WIDTH];
        for (i, word) in words.iter_mut().enumerate() {
            *word = self.0[i] ^ rhs.0[i];
        }
        Self(words)
    }
}

/// 算术符重载: ^=
impl BitXorAssign for Uint256 {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

/// 算术符重载: <<
impl Shl<u32> for Uint256 {
    type Output = Self;

    fn shl(mut self, rhs: u32) -> Self::Output {
        self <<= rhs;
        self
    }
}

/// 算术符重载: <<=
impl ShlAssign<u32> for Uint256 {
    fn shl_assign(&mut self, rhs: u32) {
        self.shl_bits_assign(rhs);
    }
}

/// 算术符重载: >>
impl Shr<u32> for Uint256 {
    type Output = Self;

    fn shr(mut self, rhs: u32) -> Self::Output {
        self >>= rhs;
        self
    }
}

/// 算术符重载: >>=
impl ShrAssign<u32> for Uint256 {
    fn shr_assign(&mut self, rhs: u32) {
        self.shr_bits_assign(rhs);
    }
}
