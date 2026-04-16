/// @Name: uint256
///
/// @Date: 2026/4/14 14:52
///
/// @Author: Matrix.Ye
///
/// @Description: 256位无符号整数类型，用于存储哈希值，参考比特币 C++ arith_uint256，采用小端字序存储

/// 256位无符号整数，采用小端字序 `[u32; 8]` 存储 (与比特币 C++ arith_uint256 一致)
/// words[0]=LSW, words[7]=MSW，每个u32内部使用小端字节序
/// ### SetCompact 算法
/// 1. 提取指数： n_size = n_compact >> 24
/// 2. 提取尾数： n_word = n_compact & 0x007fffff
/// 3. 根据指数计算目标值：
///    - 如果 n_size ≤ 3 ：右移尾数
///    - 如果 n_size > 3 ：左移尾数
/// 4. 计算符号和溢出标志
/// ### GetCompact 算法
/// 1. 计算最高有效位位置
/// 2. 计算字节数 n_size = (bits + 7) / 8
/// 3. 根据字节数提取尾数：
///    - 如果 n_size ≤ 3 ：左移获取尾数
///    - 如果 n_size > 3 ：右移后获取尾数
/// 4. 处理符号位冲突（第 24 位）
/// 5. 组合结果：指数 + 尾数 + 符号位
/// ### C++源码相关
/// arith_uint256.cpp
/// pow.cpp

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Uint256([u32; 8]);

/// `[u32,8]` => Uint256
impl From<[u32; 8]> for Uint256 {
    fn from(words: [u32; 8]) -> Self {
        Uint256(words)
    }
}

/// Uint256 => `[u32;8]`
impl From<Uint256> for [u32; 8] {
    fn from(hash: Uint256) -> Self {
        hash.0
    }
}

/// `[u8; 32]` => Uint256
impl From<[u8; 32]> for Uint256 {
    fn from(bytes: [u8; 32]) -> Self {
        let mut words = [0u32; 8];
        for i in 0..8 {
            let start = i * 4;
            words[i] = u32::from_le_bytes([
                bytes[start],
                bytes[start + 1],
                bytes[start + 2],
                bytes[start + 3],
            ]);
        }
        Uint256(words)
    }
}

/// Uint256 => `[u8;32]`
impl From<Uint256> for [u8; 32] {
    fn from(hash: Uint256) -> Self {
        hash.to_bytes()
    }
}

/// u64 => Uint256
impl From<u64> for Uint256 {
    fn from(value: u64) -> Self {
        let mut words = [0u32; 8];
        words[0] = (value & 0xffff_ffff) as u32;
        words[1] = (value >> 32) as u32;
        Uint256(words)
    }
}

/// u32 => Uint256
impl From<u32> for Uint256 {
    fn from(value: u32) -> Self {
        let mut words = [0u32; 8];
        words[0] = value;
        Uint256(words)
    }
}

/// 实现可比较
impl PartialOrd for Uint256 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
/// 实现排序
/// 小端字序下从 words[7](MSW) 到 words[0](LSW) 逐字比较，与 C++ arith_uint256 一致
impl Ord for Uint256 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        for i in (0..8).rev() {
            if self.0[i] < other.0[i] {
                return std::cmp::Ordering::Less;
            }
            if self.0[i] > other.0[i] {
                return std::cmp::Ordering::Greater;
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl Uint256 {
    /// 转换为十六进制字符串，prefix=true 时带 "0x" 前缀
    /// 输出大端显示序 (MSB在前)，与区块浏览器显示一致
    pub fn to_hex_string(&self, prefix: bool) -> String {
        let hex: String = (0..8).rev().map(|i| format!("{:08x}", self.0[i])).collect();
        if prefix { format!("0x{}", hex) } else { hex }
    }

    /// 从十六进制字符串创建，输入64字符大端显示序 (MSB在前)，支持 "0x" 前缀
    /// `hex[0..8] → words[7](MSW), hex[56..64] → words[0](LSW)`
    pub fn from_hex_string(hex: &str) -> Result<Self, String> {
        let hex = hex.trim_start_matches("0x").trim_start_matches("0X");

        if hex.len() != 64 {
            return Err(format!(
                "Invalid hex string length: expected 64, got {}",
                hex.len()
            ));
        }

        let mut words = [0u32; 8];
        for i in 0..8 {
            let start = i * 8;
            let word_index = 7 - i;
            words[word_index] = u32::from_str_radix(&hex[start..start + 8], 16)
                .map_err(|e| format!("Invalid hex at position {}: {}", start, e))?;
        }

        Ok(Uint256(words))
    }

    /// 从 `[u32; 8]` 创建，words[0] 为最低有效字 (LSW)
    pub fn from_words(value: [u32; 8]) -> Uint256 {
        Uint256(value)
    }

    /// 从 `[u8; 32]` 创建，bytes[0..4] = words[0] 小端字节 (LSW)
    pub fn from_bytes(value: [u8; 32]) -> Uint256 {
        Uint256::from(value)
    }

    /// 返回内部 `[u32; 8]`，words[0] 为最低有效字 (LSW)
    pub fn words(&self) -> [u32; 8] {
        self.0
    }

    /// 转换为 `[u8; 32]`，bytes[0..4] = words[0] 小端字节，用于序列化和哈希
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..8 {
            let word_bytes = self.0[i].to_le_bytes();
            let start = i * 4;
            bytes[start] = word_bytes[0];
            bytes[start + 1] = word_bytes[1];
            bytes[start + 2] = word_bytes[2];
            bytes[start + 3] = word_bytes[3];
        }
        bytes
    }

    /// 判断是否为零 (所有字都是0)
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&w| w == 0)
    }

    /// 返回最高有效位的位置 + 1（如果值为0则返回0）
    /// 对应 C++ 的 base_uint::bits()
    pub fn bits(&self) -> u32 {
        for pos in (0..8).rev() {
            if self.0[pos] != 0 {
                for nbits in (1..=31).rev() {
                    if (self.0[pos] & (1u32 << nbits)) != 0 {
                        return 32 * pos as u32 + nbits + 1;
                    }
                }
                return 32 * pos as u32 + 1;
            }
        }
        0
    }

    /// 返回低 64 位值
    /// 对应 C++ 的 base_uint::GetLow64()
    pub fn get_low64(&self) -> u64 {
        (self.0[0] as u64) | ((self.0[1] as u64) << 32)
    }

    /// 左移操作
    pub fn shl_assign(&mut self, shift: u32) {
        if shift == 0 {
            return;
        }

        let word_shift = (shift / 32) as usize;
        let bit_shift = shift % 32;

        if word_shift >= 8 {
            self.0 = [0u32; 8];
            return;
        }

        // 先处理字级别的移位
        if word_shift > 0 {
            for i in (word_shift..8).rev() {
                self.0[i] = self.0[i - word_shift];
            }
            for i in 0..word_shift {
                self.0[i] = 0;
            }
        }

        // 再处理位级别的移位
        if bit_shift > 0 && word_shift < 8 {
            for i in (word_shift + 1..8).rev() {
                self.0[i] = (self.0[i] << bit_shift) | (self.0[i - 1] >> (32 - bit_shift));
            }
            self.0[word_shift] <<= bit_shift;
        }
    }

    /// 右移操作
    pub fn shr_assign(&mut self, shift: u32) {
        if shift == 0 {
            return;
        }

        let word_shift = (shift / 32) as usize;
        let bit_shift = shift % 32;

        if word_shift >= 8 {
            self.0 = [0u32; 8];
            return;
        }

        // 先处理字级别的移位
        if word_shift > 0 {
            for i in 0..(8 - word_shift) {
                self.0[i] = self.0[i + word_shift];
            }
            for i in (8 - word_shift)..8 {
                self.0[i] = 0;
            }
        }

        // 再处理位级别的移位
        if bit_shift > 0 && word_shift < 8 {
            let limit = 8 - word_shift - 1;
            for i in 0..limit {
                self.0[i] = (self.0[i] >> bit_shift) | (self.0[i + 1] << (32 - bit_shift));
            }
            self.0[limit] >>= bit_shift;
        }
    }

    /// 从紧凑格式 (nBits) 转换为 Uint256
    /// 返回 (negative, overflow) 标志
    /// 对应 C++ 的 arith_uint256::SetCompact
    pub fn set_compact(n_compact: u32) -> (Self, bool, bool) {
        let n_size = (n_compact >> 24) as i32;
        let n_word = n_compact & 0x007fffff;

        let mut result = Uint256::default();

        if n_size <= 3 {
            let shift = 8 * (3 - n_size);
            result.0[0] = n_word >> shift;
        } else {
            result.0[0] = n_word;
            let shift = 8 * (n_size - 3) as u32;
            result.shl_assign(shift);
        }

        // 计算符号标志
        let negative = n_word != 0 && (n_compact & 0x00800000) != 0;

        // 计算溢出标志
        let overflow = n_word != 0
            && (n_size > 34 || (n_word > 0xff && n_size > 33) || (n_word > 0xffff && n_size > 32));

        (result, negative, overflow)
    }

    /// 将 Uint256 转换为紧凑格式
    /// 对应 C++ 的 arith_uint256::GetCompact
    pub fn get_compact(&self, negative: bool) -> u32 {
        // 计算字节数（向上取整）
        let n_size = (self.bits() + 7) / 8;

        let mut n_compact: u32;

        if n_size <= 3 {
            n_compact = (self.get_low64() << (8 * (3 - n_size))) as u32;
        } else {
            let mut bn = *self;
            let shift = 8 * (n_size - 3);
            bn.shr_assign(shift);
            n_compact = bn.get_low64() as u32;
        }

        // 第 24 位表示符号，如果已设置，则将尾数除以 256 并增加指数
        if (n_compact & 0x00800000) != 0 {
            n_compact >>= 8;
        }

        // 组合结果：指数 + 尾数 + 符号位
        let mut result = n_compact | ((n_size as u32) << 24);

        // 如果需要设置符号位
        if negative && (n_compact & 0x007fffff) != 0 {
            result |= 0x00800000;
        }

        result
    }

    /// 加法操作
    pub fn add_assign(&mut self, other: &Self) {
        let mut carry = 0u64;
        for i in 0..8 {
            let sum = carry + self.0[i] as u64 + other.0[i] as u64;
            self.0[i] = sum as u32;
            carry = sum >> 32;
        }
        // 忽略溢出
    }

    /// 减法操作（假设 self >= other）
    pub fn sub_assign(&mut self, other: &Self) {
        let mut borrow = 0u64;
        for i in 0..8 {
            let mut diff = self.0[i] as u64 - other.0[i] as u64 - borrow;
            if diff > 0xffff_ffff {
                diff += 0x1_0000_0000;
                borrow = 1;
            } else {
                borrow = 0;
            }
            self.0[i] = diff as u32;
        }
    }

    /// 乘法操作（与 u32 相乘）
    pub fn mul_assign_u32(&mut self, other: u32) {
        let mut carry = 0u64;
        for i in 0..8 {
            let product = carry + (self.0[i] as u64) * (other as u64);
            self.0[i] = product as u32;
            carry = product >> 32;
        }
    }
}

// 实现运算符重载

// 左移运算符
impl std::ops::ShlAssign<u32> for Uint256 {
    fn shl_assign(&mut self, rhs: u32) {
        self.shl_assign(rhs);
    }
}

impl std::ops::Shl<u32> for Uint256 {
    type Output = Self;
    fn shl(self, rhs: u32) -> Self::Output {
        let mut result = self;
        result.shl_assign(rhs);
        result
    }
}

// 右移运算符
impl std::ops::ShrAssign<u32> for Uint256 {
    fn shr_assign(&mut self, rhs: u32) {
        self.shr_assign(rhs);
    }
}

impl std::ops::Shr<u32> for Uint256 {
    type Output = Self;
    fn shr(self, rhs: u32) -> Self::Output {
        let mut result = self;
        result.shr_assign(rhs);
        result
    }
}

// 加法运算符
impl std::ops::AddAssign<&Uint256> for Uint256 {
    fn add_assign(&mut self, rhs: &Uint256) {
        self.add_assign(rhs);
    }
}

impl std::ops::Add<&Uint256> for Uint256 {
    type Output = Self;
    fn add(self, rhs: &Uint256) -> Self::Output {
        let mut result = self;
        result.add_assign(rhs);
        result
    }
}

impl std::ops::AddAssign<Uint256> for Uint256 {
    fn add_assign(&mut self, rhs: Uint256) {
        self.add_assign(&rhs);
    }
}

impl std::ops::Add<Uint256> for Uint256 {
    type Output = Self;
    fn add(self, rhs: Uint256) -> Self::Output {
        self + &rhs
    }
}

// 减法运算符
impl std::ops::SubAssign<&Uint256> for Uint256 {
    fn sub_assign(&mut self, rhs: &Uint256) {
        self.sub_assign(rhs);
    }
}

impl std::ops::Sub<&Uint256> for Uint256 {
    type Output = Self;
    fn sub(self, rhs: &Uint256) -> Self::Output {
        let mut result = self;
        result.sub_assign(rhs);
        result
    }
}

impl std::ops::SubAssign<Uint256> for Uint256 {
    fn sub_assign(&mut self, rhs: Uint256) {
        self.sub_assign(&rhs);
    }
}

impl std::ops::Sub<Uint256> for Uint256 {
    type Output = Self;
    fn sub(self, rhs: Uint256) -> Self::Output {
        self - &rhs
    }
}

// 乘法运算符（与 u32 相乘）
impl std::ops::MulAssign<u32> for Uint256 {
    fn mul_assign(&mut self, rhs: u32) {
        self.mul_assign_u32(rhs);
    }
}

impl std::ops::Mul<u32> for Uint256 {
    type Output = Self;
    fn mul(self, rhs: u32) -> Self::Output {
        let mut result = self;
        result.mul_assign_u32(rhs);
        result
    }
}

// 比较运算符
impl std::ops::Add<u64> for Uint256 {
    type Output = Self;
    fn add(self, rhs: u64) -> Self::Output {
        let mut result = self;
        result.0[0] = (result.0[0] as u64 + (rhs & 0xffff_ffff)) as u32;
        result.0[1] = (result.0[1] as u64 + (rhs >> 32)) as u32;
        result
    }
}

impl std::ops::AddAssign<u64> for Uint256 {
    fn add_assign(&mut self, rhs: u64) {
        *self = *self + rhs;
    }
}
