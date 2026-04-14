/// @Name: uint256
///
/// @Date: 2026/4/14 14:52
///
/// @Author: Matrix.Ye
///
/// @Description: 256位无符号整数类型，用于存储哈希值

/// 256位无符号整数，通常用于存储双重 SHA256 哈希值
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Uint256([u8; 32]);

// 实现 From<[u8; 32]>，支持 .into() 转换
impl From<[u8; 32]> for Uint256 {
    fn from(bytes: [u8; 32]) -> Self {
        Uint256(bytes)
    }
}

// 实现 From<Uint256> for [u8; 32]，支持反向转换
impl From<Uint256> for [u8; 32] {
    fn from(hash: Uint256) -> Self {
        hash.0
    }
}

// 实现 PartialOrd，支持部分比较 (>, <, >=, <=)
impl PartialOrd for Uint256 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// 实现 Ord，支持全序比较，用于排序
// 按字典序比较(从第一个字节开始比较)
impl Ord for Uint256 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl Uint256 {
    /// 将 Uint256 转换为十六进制字符串
    ///
    /// # 返回值
    ///
    /// * `String` - 64个字符的十六进制字符串(不含 "0x" 前缀)
    pub fn to_hex_string(&self) -> String {
        self.0.iter().map(|byte| format!("{:02x}", byte)).collect()
    }

    /// 将 Uint256 转换为带 "0x" 前缀的十六进制字符串
    ///
    /// # 返回值
    ///
    /// * `String` - 66个字符的十六进制字符串(含 "0x" 前缀)
    pub fn to_hex_prefix_string(&self) -> String {
        format!("0x{}", self.to_hex_string())
    }

    /// 从十六进制字符串创建 Uint256
    ///
    /// # 参数
    ///
    /// * `hex` - 十六进制字符串(可以有或没有 "0x" 前缀)
    ///
    /// # 返回值
    ///
    /// * `Result<Uint256, String>` - 成功返回 Uint256, 失败返回错误信息
    pub fn from_hex_string(hex: &str) -> Result<Self, String> {
        // 移除 "0x" 或 "0X" 前缀
        let hex = hex.trim_start_matches("0x").trim_start_matches("0X");

        if hex.len() != 64 {
            return Err(format!(
                "Invalid hex string length: expected 64, got {}",
                hex.len()
            ));
        }

        let mut bytes = [0u8; 32];
        for i in 0..32 {
            bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|e| format!("Invalid hex character at position {}: {}", i * 2, e))?;
        }

        Ok(Uint256(bytes))
    }

    pub fn from_bytes(value: [u8; 32]) -> Uint256 {
        Uint256(value)
    }

    /// 判断是否为零(所有字节都是0)
    ///
    /// # 返回值
    ///
    /// * `bool` - 如果所有字节都是0则返回 true
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    pub fn value(&self) -> [u8; 32] {
        self.0
    }
}
