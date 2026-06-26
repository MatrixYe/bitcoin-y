/// @Name: bignum
///
/// @Date: 2026/5/15 17:35
///
/// @Author: Matrix.Ye
///
/// @Description: null
use crate::uint256::Uint256;
use num_bigint::{BigInt, Sign};
use num_traits::{FromPrimitive, Signed, ToPrimitive, Zero};
use std::fmt;
use std::ops::{
    Add, AddAssign, Div, DivAssign, Mul, MulAssign, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign,
    Sub, SubAssign,
};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BigNumError {
    #[error("bignum value cannot fit into {target}")]
    PrimitiveOverflow { target: &'static str }, // 转化溢出，参考i8~i128,u8~u128的数据范围

    #[error("invalid hex string: {0}")]
    InvalidHex(String), // Bignum <-> Hex
}

// 原版比特币是引用opssl 的bigint库
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BigNum(BigInt);
impl BigNum {
    pub const ZERO: Self = Self(BigInt::ZERO);
}
impl BigNum {
    /// 从 Rust `usize` 构造 BigNum
    pub fn from_usize(value: usize) -> Self {
        BigNum(BigInt::from(value))
    }

    pub fn from_u8(value: u8) -> Self {
        BigNum(BigInt::from(value))
    }

    /// 从 Rust `u32` 构造 BigNum,对应原版中较小无符号整数构造函数的常用语义。
    pub fn from_u32(value: u32) -> Self {
        BigNum(BigInt::from(value))
    }

    /// 从 Rust `u64` 构造 BigNum,对应原版 `CBigNum(uint64 n)`。
    pub fn from_u64(value: u64) -> Self {
        BigNum(BigInt::from(value))
    }

    /// 从 Rust `u128` 构造 BigNum
    pub fn from_u128(value: u128) -> Self {
        BigNum(BigInt::from(value))
    }

    /// 从 Rust `i8` 构造 BigNum
    pub fn from_i8(value: i8) -> Self {
        BigNum(BigInt::from(value))
    }

    /// 从 Rust `i32` 构造 BigNum,对应原版 `CBigNum(int n)`
    pub fn from_i32(value: i32) -> Self {
        BigNum(BigInt::from(value))
    }

    /// 从 Rust `i64` 构造 BigNum,对应原版 `CBigNum(int64 n)`
    pub fn from_i64(value: i64) -> Self {
        BigNum(BigInt::from(value))
    }

    /// 从 Rust `i128` 构造 BigNum,对应原版
    pub fn from_i128(value: i128) -> Self {
        BigNum(BigInt::from(value))
    }

    /// 从十六进制字符串构造 BigNum。
    /// 和原版不一样，我使用更严格的 Rust 语义：除可选正负号、前后空白和 `0x` / `0X` 前缀外，
    /// 剩余内容必须全部是十六进制字符。
    pub fn from_hex(hex: &str) -> Result<Self, BigNumError> {
        // 空格移除
        let mut value = hex.trim();

        // 判断正负号
        let negative = match value.as_bytes().first() {
            Some(b'-') => {
                value = value[1..].trim_start();
                true
            }
            Some(b'+') => {
                value = value[1..].trim_start();
                false
            }
            _ => false,
        };

        // 移除0x或者0X
        value = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .unwrap_or(value);

        // 空处理，0x 表示0
        if value.is_empty() {
            return Ok(BigNum::zero());
        }

        // 字符串字符判断
        if !value.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(BigNumError::InvalidHex(hex.to_string()));
        }
        // 按照16进制，解析每个字符为字节`1 -> 1u8`,`f -> 15u8`
        // 字节流 转化为 BigInt
        let n = BigInt::parse_bytes(value.as_bytes(), 16)
            .ok_or_else(|| BigNumError::InvalidHex(hex.to_string()))?;

        // 匹配正负号
        match negative {
            true => Ok(BigNum(-n)),
            false => Ok(BigNum(n)),
        }
    }

    /// 从 Uint256 构造 BigNum，对应原版 `CBigNum(uint256 n)`
    pub fn from_uint256(value: Uint256) -> Self {
        BigNum(BigInt::from_bytes_le(Sign::Plus, &value.to_bytes()))
    }

    /// nbits => bnTarget
    pub fn set_compact(nbits: u32) -> Self {
        // 取前8位，作为指数
        let exponent = nbits >> 24;
        //取后24位，忽略首位，作为尾数
        let mantissa = nbits & 0x007f_ffff;
        // 从尾数中截取首位作为符号位，等价于nbits & 0b0000_0000_1000_0000_0000_0000_0000
        let sign = nbits & 0x0080_0000 != 0;

        // 尾值
        let mut value = BigInt::from(mantissa);

        // 求值
        match exponent <= 3 {
            true => value >>= 8 * (3 - exponent),
            false => value <<= 8 * (exponent - 3),
        }
        // 正负号
        match sign & (mantissa != 0) {
            true => BigNum(-value),
            false => BigNum(value),
        }
    }

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
    /// - `[0x80,0x80]` -> `0x8080` -> `10000000 10000000` -> `-128`
    /// - `[0x80,0x00]` -> `0x0080` -> `10000000 00000000` -> `128`
    pub fn from_bytes_le(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return BigNum::zero();
        }

        let mut bytes = bytes.to_vec();
        let last_index = bytes.len() - 1;
        let negative = has_sign(bytes[last_index]); // 判断正负号
        bytes[last_index] = remove_sign(bytes[last_index]); // 绝对值化
        let value = BigInt::from_bytes_le(Sign::Plus, &bytes);
        match negative {
            true => BigNum(-value),
            false => BigNum(value),
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
        let has_sign = has_sign(*last_byte);

        match (is_negative, has_sign) {
            // 是负数，有符号标识 => 追加0x80
            (true, true) => bytes.push(0x80),
            // 是负数，没有符号标识 => 最高位字节的最高比特位设置为1
            (true, false) => *last_byte |= 0x80,
            // 是正数，有符号标识 => 追加一个正符号
            (false, true) => bytes.push(0x00),
            // 是正数，没有符号标识 => 无需处理
            (false, false) => {}
        }
        bytes
    }

    /// 转换为 `usize`，超出目标类型范围时返回错误。
    pub fn to_usize(&self) -> Result<usize, BigNumError> {
        self.0
            .to_usize()
            .ok_or(BigNumError::PrimitiveOverflow { target: "usize" })
    }

    /// 转换为 `i8`，超出目标类型范围时返回错误。
    pub fn to_i8(&self) -> Result<i8, BigNumError> {
        self.0
            .to_i8()
            .ok_or(BigNumError::PrimitiveOverflow { target: "i8" })
    }

    /// 转换为 `i64`，超出目标类型范围时返回错误。
    pub fn to_i64(&self) -> Result<i64, BigNumError> {
        self.0
            .to_i64()
            .ok_or(BigNumError::PrimitiveOverflow { target: "i64" })
    }

    /// 转换为 `u32`，负数或超出 `u32` 范围时返回错误。
    pub fn to_u32(&self) -> Result<u32, BigNumError> {
        self.0
            .to_u32()
            .ok_or(BigNumError::PrimitiveOverflow { target: "u32" })
    }

    /// 转换为十六进制字符串。
    ///
    /// 输出不带 `0x` 前缀，负数使用 `-` 前缀。
    pub fn to_hex(&self) -> String {
        self.to_string_base(16)
    }

    /// 按指定进制转换为字符串。
    ///
    /// 原版 `ToString` 默认使用 10 进制，`GetHex` 使用 16 进制。
    pub fn to_string_base(&self, radix: u32) -> String {
        self.0.to_str_radix(radix)
    }

    /// 转换为 Uint256，对应原版 `CBigNum::getuint256()`
    ///
    /// 原版会忽略符号，并只取低 256 位；这里保持这个语义
    pub fn to_uint256(&self) -> Uint256 {
        let (_, bytes) = self.0.abs().to_bytes_le();
        let mut uint_bytes = [0u8; 32];
        let len = bytes.len().min(uint_bytes.len());
        uint_bytes[..len].copy_from_slice(&bytes[..len]);
        Uint256::from_bytes(uint_bytes)
    }

    /// bnTarget => nbits
    ///
    /// 这里按原版 `CBigNum::GetCompact()` 的 MPI 语义编码，负数会把符号位写入 compact。
    pub fn get_compact(&self) -> u32 {
        if self.is_zero() {
            return 0;
        }

        let is_negative = self.is_negative();
        let (_, mut bytes) = self.0.abs().to_bytes_be();

        match (is_negative, has_sign(bytes[0])) {
            // 负数且最高位已经占用，需要额外插入一个带符号字节
            (true, true) => bytes.insert(0, 0x80),
            // 负数且最高位未占用，直接把首字节最高位置 1
            (true, false) => bytes[0] |= 0x80,
            // 正数且最高位已经占用，需要插入 0，避免被 MPI 解释成负数
            (false, true) => bytes.insert(0, 0x00),
            // 正数且最高位未占用，无需处理
            (false, false) => {}
        }

        let n_size = bytes.len() as u32;
        let mut n_compact = n_size << 24;
        if n_size >= 1 {
            n_compact |= (bytes[0] as u32) << 16;
        }
        if n_size >= 2 {
            n_compact |= (bytes[1] as u32) << 8;
        }
        if n_size >= 3 {
            n_compact |= bytes[2] as u32;
        }
        n_compact
    }

    pub fn to_bool(&self) -> bool {
        !self.0.is_zero()
    }

    /// 序列化 BigNum，当前先保留 API，后续再对齐项目统一序列化规则。
    pub fn serialize(&self) -> Vec<u8> {
        unimplemented!("BigNum::serialize is not implemented yet")
    }

    /// 反序列化 BigNum，当前先保留 API，后续再对齐项目统一序列化规则。
    pub fn unserialize(_bytes: &[u8]) -> Self {
        unimplemented!("BigNum::unserialize is not implemented yet")
    }

    /// 是否为0,0 => true,ther -> false
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// 是否不为0
    pub fn is_not_zero(&self) -> bool {
        !self.is_zero()
    }

    /// 是否为负数,负数->true,正数/零 -> false
    pub fn is_negative(&self) -> bool {
        self.0.is_negative()
    }

    /// 是否为正数，正数:true,负数:false
    pub fn is_positive(&self) -> bool {
        self.0.is_positive()
    }

    /// 设置为0
    pub fn zero() -> Self {
        BigNum(BigInt::zero())
    }

    /// 贴近原版 CBigNum::operator>>= 的保护逻辑：
    /// 如果 1*2^shift 大于当前值，直接返回 0，避免底层右移在旧 OpenSSL 上的异常行为。
    /// ```cpp
    /// CBigNum a = 1;
    /// a <<= shift;
    /// if (BN_cmp(&a, this) > 0)
    /// {
    /// *this = 0;
    /// return *this;
    /// }
    /// BN_rshift(this, this, shift);
    /// ```

    fn shr_like_cpp(mut self, shift: u32) -> Self {
        let threshold = BigInt::from(1u8) << shift as usize;
        match threshold > self.0 {
            true => BigNum::zero(),
            false => {
                self.0 >>= shift as usize;
                self
            }
        }
    }
}

/// 工具函数：判断单字节是否包含符号，即最高bit位是否不为0
///
/// `0001 0000` & `1000 0000` = `0000 0000` =0  => unSigned
///
/// `1000 1000` & `1000 0000` = `1000 0000` !=0 => Signed
fn has_sign(x: u8) -> bool {
    x & 0b1000_0000 != 0
}

/// 工具函数：移除单字节的符号，即最高比特位设置为0，其余比特位不变
///
/// `0001_0000` & `0111_1111` = `0001_0000`
///
/// `1000_1000` & `0111_1111` = `0000_1000`
fn remove_sign(x: u8) -> u8 {
    x & 0b0111_1111
}

/// 默认数值：BigNum(0)
impl Default for BigNum {
    fn default() -> Self {
        Self::zero()
    }
}

impl From<Uint256> for BigNum {
    fn from(value: Uint256) -> Self {
        Self::from_uint256(value)
    }
}

impl From<BigNum> for Uint256 {
    fn from(value: BigNum) -> Self {
        value.to_uint256()
    }
}

impl From<&BigNum> for Uint256 {
    fn from(value: &BigNum) -> Self {
        value.to_uint256()
    }
}

/// rust风味的to_string,转成十进制的字符串格式
impl fmt::Display for BigNum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_base(10))
    }
}

//------------------------运算符重载-------------------------------//
// 算术运算符需要单独实现。
// 比较运算符已经通过特征属性来交给编译器自动实现，无需像CPP一样手动再实现一遍。因此对于
// operator==
// operator!=
// operator<
// operator>
// operator<=
// operator>=
// 的实现已经跳过。

impl BigNum {
    // +1
    pub fn add_one(self) -> Self {
        self.add(BigNum::from_u32(1))
    }
    // -1
    pub fn sub_one(self) -> Self {
        self.sub(BigNum::from_u32(1))
    }
    // *2
    pub fn mul_two(self) -> Self {
        self.mul(BigNum::from_u32(2))
    }
    // /2
    pub fn div_two(self) -> Self {
        self.div(BigNum::from_u32(2))
    }
    // -x
    pub fn negate(self) -> Self {
        BigNum(-self.0)
    }
    // 获取绝对值
    pub fn abs(self) -> Self {
        BigNum(self.0.abs())
    }
}

/// 算术运算: +
impl Add for BigNum {
    type Output = BigNum;
    fn add(self, rhs: Self) -> Self::Output {
        BigNum(self.0 + rhs.0)
    }
}
/// 算术运算: +=
impl AddAssign for BigNum {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

/// 算术运算: 减:-
impl Sub for BigNum {
    type Output = BigNum;
    fn sub(self, rhs: Self) -> Self::Output {
        BigNum(self.0 - rhs.0)
    }
}

/// 算术运算: -=
impl SubAssign for BigNum {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

/// 算术运算: *
impl Mul for BigNum {
    type Output = BigNum;
    fn mul(self, rhs: Self) -> Self::Output {
        BigNum(self.0 * rhs.0)
    }
}
/// 算术运算: *=
impl MulAssign for BigNum {
    fn mul_assign(&mut self, rhs: Self) {
        self.0 *= rhs.0;
    }
}

/// 算术运算:  /
impl Div for BigNum {
    type Output = BigNum;
    fn div(self, rhs: Self) -> Self::Output {
        BigNum(self.0 / rhs.0)
    }
}

/// 算术运算: /=
impl DivAssign for BigNum {
    fn div_assign(&mut self, rhs: Self) {
        self.0 /= rhs.0;
    }
}

/// 算术运算: %
impl Rem for BigNum {
    type Output = BigNum;
    fn rem(self, rhs: Self) -> Self::Output {
        BigNum(self.0 % rhs.0)
    }
}

/// 算术运算: %=
impl RemAssign for BigNum {
    fn rem_assign(&mut self, rhs: Self) {
        self.0 %= rhs.0;
    }
}

/// 位运算: <<
impl Shl<u32> for BigNum {
    type Output = BigNum;
    fn shl(self, rhs: u32) -> Self::Output {
        BigNum(self.0 << rhs as usize)
    }
}

/// 位运算: <<=
impl ShlAssign<u32> for BigNum {
    fn shl_assign(&mut self, rhs: u32) {
        self.0 <<= rhs as usize;
    }
}

/// 位运算: >>
impl Shr<u32> for BigNum {
    type Output = BigNum;
    fn shr(self, rhs: u32) -> Self::Output {
        self.shr_like_cpp(rhs)
    }
}
/// 位运算:  >>=
impl ShrAssign<u32> for BigNum {
    fn shr_assign(&mut self, rhs: u32) {
        *self = self.clone().shr_like_cpp(rhs);
    }
}
