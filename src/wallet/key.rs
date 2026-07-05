use crate::hash::hash160;
use secp256k1::ecdsa::Signature;
use secp256k1::{rand, Message, PublicKey, SecretKey};
use secp256k1::{All, Secp256k1};
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
    #[error("invalid private key")]
    InvalidPrivateKey,

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid ECDSA signature")]
    InvalidSignature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateKey(pub SecretKey);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PubKey(pub PublicKey);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaSignature(pub Signature);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPair {
    private_key: PrivateKey,
    public_key: PubKey,
}

impl KeyPair {
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

    pub fn private_key(&self) -> PrivateKey {
        self.private_key
    }

    pub fn public_key(&self) -> PubKey {
        self.public_key
    }
}

impl PrivateKey {
    /// 从原始私钥字节创建 secp256k1 私钥。
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, KeyError> {
        SecretKey::from_byte_array(bytes)
            .map(Self)
            .map_err(|_| KeyError::InvalidPrivateKey)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.secret_bytes()
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
}

impl PubKey {
    /// 从压缩或未压缩公钥字节创建公钥。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        PublicKey::from_slice(bytes)
            .map(Self)
            .map_err(|_| KeyError::InvalidPublicKey)
    }

    pub fn to_bytes_uncompressed(&self) -> [u8; 65] {
        self.0.serialize_uncompressed()
    }

    pub fn to_bytes_compressed(&self) -> [u8; 33] {
        self.0.serialize()
    }

    /// v0.3.19 更接近未压缩公钥语义，默认导出未压缩字节。
    pub fn to_bytes(&self) -> [u8; 65] {
        self.to_bytes_uncompressed()
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
}

impl EcdsaSignature {
    pub fn from_der(bytes: &[u8]) -> Result<Self, KeyError> {
        Signature::from_der(bytes).map(Self).map_err(|_| KeyError::InvalidSignature)
    }

    pub fn to_der(&self) -> Vec<u8> {
        self.0.serialize_der().to_vec()
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

/// 计算 `HASH160(pubkey)`，用于 P2PKH 地址和脚本模板。
pub fn hash160_pubkey(pub_key: PubKey) -> [u8; 20] {
    hash160(&pub_key.to_bytes())
}
