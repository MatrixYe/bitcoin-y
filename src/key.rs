use crate::errors::CError;
use hex;
use ripemd::Ripemd160;
use secp256k1::ecdsa::Signature;
use secp256k1::hashes::{sha256, Hash};
use secp256k1::{rand, PublicKey, SecretKey};
use secp256k1::{All, Message, Secp256k1};
use sha2::{Digest, Sha256};
/// @Name key.rs
///
/// @Date 2025/12/28 22:05
///
/// @Author Matrix.Ye
///
/// @Description: 密钥对工具
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct KeyPair {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
}

impl KeyPair {
    #[allow(dead_code)]
    pub fn new() -> Self {
        let secp: Secp256k1<All> = Secp256k1::<All>::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut rand::rng());
        Self {
            secret_key,
            public_key,
        }
    }

    #[allow(dead_code)]
    pub fn get_public_key(&self) -> String {
        hex::encode(self.public_key.serialize())
    }
    #[allow(dead_code)]
    pub fn get_secret_key(&self) -> String {
        hex::encode(self.secret_key.secret_bytes())
    }

    // 生成比特币地址：地址=版本号+双哈希+校验码
    #[allow(dead_code)]
    pub fn to_address(&self) -> String {
        let pk = self.public_key.serialize(); //公钥

        let sha256 = Sha256::digest(pk); //公钥第一次哈希

        let ripemd160 = Ripemd160::digest(sha256); //公钥第二次哈希

        let mut payload = Vec::with_capacity(1 + 20 + 4); //负载=版本号+双哈希+校验码

        payload.push(0x00); //添加版本号，主网为0x00

        payload.extend_from_slice(ripemd160.as_slice()); //添加公钥双哈希

        let checksum = Sha256::digest(Sha256::digest(&payload)); //取前4个字节作为校验码

        payload.extend_from_slice(&checksum[..4]);
        bs58::encode(payload).into_string() //base58编码
    }
}

// SecretKey ==> KeyPair
impl From<SecretKey> for KeyPair {
    fn from(secret_key: SecretKey) -> Self {
        let secp = Secp256k1::<All>::new();
        let public_key = secret_key.public_key(&secp);
        KeyPair {
            secret_key,
            public_key,
        }
    }
}
// &str ==> KeyPair
impl TryFrom<&str> for KeyPair {
    type Error = CError;

    fn try_from(secret_key_hex: &str) -> Result<Self, Self::Error> {
        if secret_key_hex.len() != 64 {
            return Err(CError::InvalidHexLength(64, secret_key_hex.len() as u32));
        }
        let mut secret_key_bytes = [0u8; 32];
        hex::decode_to_slice(secret_key_hex, &mut secret_key_bytes)
            .map_err(|_| CError::InvalidHexLength(64, secret_key_hex.len() as u32))?;

        let secret_key: SecretKey =
            SecretKey::from_byte_array(secret_key_bytes).map_err(|_| CError::InvalidSecretKey)?;

        Ok(secret_key.into())
    }
}

// String ==> KeyPair
impl TryFrom<String> for KeyPair {
    type Error = CError;

    fn try_from(secret_key_hex: String) -> Result<Self, Self::Error> {
        secret_key_hex.as_str().try_into()
    }
}
// [u8; 32] ==> KeyPair
impl TryFrom<[u8; 32]> for KeyPair {
    type Error = CError;

    fn try_from(secret_key_bytes: [u8; 32]) -> Result<Self, Self::Error> {
        let secret_key: SecretKey =
            SecretKey::from_byte_array(secret_key_bytes).map_err(|_| CError::InvalidSecretKey)?;
        Ok(secret_key.into())
    }
}

// 对内容进行签名，返回数字签名Signature
#[allow(dead_code)]
pub fn sign(keypair: &KeyPair, content: &[u8]) -> Signature {
    let secp: Secp256k1<All> = Secp256k1::<All>::new();
    let digest: sha256::Hash = sha256::Hash::hash(content);
    let message = Message::from_digest(digest.to_byte_array());
    secp.sign_ecdsa(message, &keypair.secret_key)
}

// 验证签名，返回是否验证成功
#[allow(dead_code)]
pub fn verify(content: &[u8], public_key: &PublicKey, sig: &Signature) -> bool {
    let secp = Secp256k1::<All>::new();
    let digest = sha256::Hash::hash(content);
    let message = Message::from_digest(digest.to_byte_array());
    secp.verify_ecdsa(message, sig, public_key).is_ok()
}
