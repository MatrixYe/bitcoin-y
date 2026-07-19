use secp256k1::ecdsa::Signature;
use secp256k1::{All, Secp256k1};
use secp256k1::{Message, PublicKey, SecretKey, rand};
use thiserror::Error;

/// @Name key.rs
///
/// @Date 2025/12/28 22:05
///
/// @Author Matrix.Ye
///
/// @Description: 钱包密钥类型层。这里只处理 secp256k1 密钥、签名和公钥哈希，不处理钱包状态。

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyError {
    // 无效私钥
    #[error("invalid private key")]
    InvalidPrivateKey,

    // 无效公钥
    #[error("invalid public key")]
    InvalidPublicKey,

    // 无效的ECDSA签名
    #[error("invalid ECDSA signature")]
    InvalidSignature,
}

/// 公钥的类型
/// 1. Compressed: 压缩版本，32字节
/// 2. Uncompressed： 不压缩版本，65字节
/// 为了语义的清晰，同时避免堆内存分配的性能损耗，我没有直接使用`&[u8]`或者`Vec`,而是定义PubKeyBytes枚举
pub enum PubKeyBytes {
    Compressed { bytes: [u8; 33] },
    Uncompressed { bytes: [u8; 65] },
}

/// 私钥
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateKey(SecretKey);

/// 公钥
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PubKey(PublicKey);

/// ECDS签名
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaSignature(Signature);

/// 密钥对
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPair {
    private_key: PrivateKey,
    public_key: PubKey,
}

impl PrivateKey {
    /// 32字节 => 私钥
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, KeyError> {
        SecretKey::from_byte_array(bytes)
            .map(|s| Self(s))
            .map_err(|_| KeyError::InvalidPrivateKey)
    }

    /// 私钥 => 字节(32bytes=256bit)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.secret_bytes()
    }

    /// 十六进制私钥字符串 => 私钥
    pub fn from_hex(s: &str) -> Result<Self, KeyError> {
        let data = hex::decode(s).map_err(|_| KeyError::InvalidPrivateKey)?;
        let data: [u8; 32] = data.try_into().map_err(|_| KeyError::InvalidPrivateKey)?;
        Self::from_bytes(data)
    }

    /// 私钥 => 十六进制字符串
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
}

impl PubKeyBytes {
    // 转成字节切片
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            PubKeyBytes::Compressed { bytes } => bytes,
            PubKeyBytes::Uncompressed { bytes } => bytes,
        }
    }

    // 获取长度
    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    // 判断是否为压缩
    pub fn is_compressed(&self) -> bool {
        matches!(self, PubKeyBytes::Compressed { .. })
    }
}
impl PubKey {
    /// 从压缩或未压缩公钥字节创建公钥
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        PublicKey::from_slice(bytes)
            .map(|x| Self(x))
            .map_err(|_| KeyError::InvalidPublicKey)
    }

    /// 根据调用方选择导出压缩或未压缩公钥字节。
    ///
    /// 压缩公钥是 33 字节，未压缩公钥是 65 字节，二者长度不同。
    pub fn serailaze(&self, compress: bool) -> PubKeyBytes {
        match compress {
            true => PubKeyBytes::Compressed {
                bytes: self.0.serialize(),
            },
            false => PubKeyBytes::Uncompressed {
                bytes: self.0.serialize_uncompressed(),
            },
        }
    }

    /// 十六进制字符串显示公钥
    pub fn to_hex(&self, compress: bool) -> String {
        hex::encode(self.serailaze(compress).as_bytes())
    }
}

/// Ecdsa签名 EcdsaSignature：
///
/// 对于 Bitcoin Script 交易签名，优先使用 DER 编码，再追加 1 字节 sighash type
impl EcdsaSignature {
    ///将 DER 编码的字节切片转换为签名
    pub fn from_der(bytes: &[u8]) -> Result<Self, KeyError> {
        Signature::from_der(bytes)
            .map(|s| Self(s))
            .map_err(|_| KeyError::InvalidSignature)
    }

    pub fn to_der(&self) -> Vec<u8> {
        self.0.serialize_der().to_vec()
    }

    pub fn from_compact(v: &[u8]) -> Result<Self, KeyError> {
        Signature::from_compact(v)
            .map(Self)
            .map_err(|_| KeyError::InvalidSignature)
    }

    pub fn to_compact(&self) -> Vec<u8> {
        self.0.serialize_compact().to_vec()
    }

    pub fn from_compact_hex(s: &str) -> Result<Self, KeyError> {
        // 不要使用s.as_bytes()，这会把字符串
        hex::decode(s)
            .map_err(|_| KeyError::InvalidSignature)
            .and_then(|bytes| Self::from_compact(&bytes))
    }

    pub fn to_compact_hex(&self) -> String {
        hex::encode(self.0.serialize_compact())
    }

    pub fn from_der_hex(s: &str) -> Result<Self, KeyError> {
        hex::decode(s)
            .map_err(|_| KeyError::InvalidSignature)
            .and_then(|bytes| Self::from_der(&bytes))
    }

    pub fn to_der_hex(&self) -> String {
        hex::encode(self.to_der())
    }
}

impl KeyPair {
    /// 随机生成密钥对
    pub fn generate() -> Self {
        let secp: Secp256k1<All> = Secp256k1::<All>::new();
        let (sk, pk) = secp.generate_keypair(&mut rand::rng());
        KeyPair {
            private_key: PrivateKey(sk),
            public_key: PubKey(pk),
        }
    }

    /// 通过 32 字节私钥恢复密钥对，同时派生对应公钥。
    pub fn from_private_key(bytes: [u8; 32]) -> Result<Self, KeyError> {
        let private_key = PrivateKey::from_bytes(bytes)?;
        let secp = Secp256k1::<All>::new();
        let public_key = PubKey(private_key.0.public_key(&secp));
        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// 读取私钥
    pub fn private_key(&self) -> PrivateKey {
        self.private_key
    }

    /// 读取公钥
    pub fn public_key(&self) -> PubKey {
        self.public_key
    }
}

/// 对 32 字节摘要做 ECDSA 签名。
///
/// Bitcoin 交易签名应先由 `SignatureHash` 生成摘要；这里不直接签原始交易或任意内容。
pub fn sign_digest(private_key: PrivateKey, digest: [u8; 32]) -> EcdsaSignature {
    let secp = Secp256k1::<All>::new();
    let message = Message::from_digest(digest);
    EcdsaSignature(secp.sign_ecdsa(message, &private_key.0))
}

/// 验证 32 字节摘要上的 ECDSA 签名。
pub fn verify_digest(pub_key: PubKey, digest: [u8; 32], signature: &EcdsaSignature) -> bool {
    let secp = Secp256k1::<All>::new();
    let message = Message::from_digest(digest);
    secp.verify_ecdsa(message, &signature.0, &pub_key.0).is_ok()
}
