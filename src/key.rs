use hex;
use ripemd::Ripemd160;
use secp256k1::ecdsa::Signature;
use secp256k1::hashes::{Hash, sha256};
use secp256k1::{All, Message, Secp256k1};
use secp256k1::{PublicKey, SecretKey, rand};
use sha2::{Digest, Sha256};
/// @Name key.rs
///
/// @Date 2025/11/02 22:05
///
/// @Author Matrix.Ye
///
/// @Description: 密钥对工具
#[derive(Debug, Clone)]
pub struct Keypair {
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl Keypair {
    // 随机生成一个密钥对，返回Keypair结构体
    pub fn new() -> Self {
        let secp = Secp256k1::<All>::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
        Self {
            secret_key,
            public_key,
        }
    }

    // 从私钥创建一个密钥对，返回Keypair
    pub fn from_sk(secret_key: SecretKey) -> Self {
        let secp = Secp256k1::<All>::new();
        let public_key = secret_key.public_key(&secp);
        Keypair {
            secret_key,
            public_key,
        }
    }

    // 从私钥字符串创建一个密钥对，返回keypair
    pub fn from_sk_hex(secret_key_hex: &str) -> Self {
        let mut secret_key_bytes = [0u8; 32];
        hex::decode_to_slice(secret_key_hex, &mut secret_key_bytes).unwrap();
        let secret_key: SecretKey = SecretKey::from_byte_array(secret_key_bytes).unwrap();
        let secp = Secp256k1::<All>::new();
        let public_key = secret_key.public_key(&secp);
        Self {
            secret_key,
            public_key,
        }
    }
    // 获取公钥(十六进制字符串)
    pub fn get_public_key(&self) -> String {
        hex::encode(self.public_key.serialize())
    }
    // 获取私钥(十六进制字符串)
    pub fn get_secret_key(&self) -> String {
        hex::encode(self.secret_key.secret_bytes())
    }

    // 生成比特币地址：地址=版本号+双哈希+校验码
    pub fn to_address(&self) -> String {
        let x = 1;
        let pk = self.public_key.serialize(); //公钥
        let sha256 = Sha256::digest(pk); //公钥第一次哈希
        let ripemd160 = Ripemd160::digest(sha256); //公钥第二次哈希
        let mut payload = Vec::with_capacity(1 + 20 + 4); //负载=版本号+双哈希+校验码
        payload.push(0x00); //添加版本号，主网为0x00
        payload.extend_from_slice(ripemd160.as_slice()); //添加公钥双哈希
        let checksum = Sha256::digest(Sha256::digest(&payload)); //取前4字节作为校验码
        payload.extend_from_slice(&checksum[..4]);

        bs58::encode(payload).into_string() //base58编码
    }
}

// 使用私钥进行签名，返回数字签名Signature
pub fn sign(keypair: &Keypair, content: &[u8]) -> Signature {
    let secp = Secp256k1::<All>::new();
    let digest = sha256::Hash::hash(content);
    let message = Message::from_digest(digest.to_byte_array());
    secp.sign_ecdsa(message, &keypair.secret_key)
}

// 验证签名，返回是否验证成功
pub fn verify(content: &[u8], public_key: &PublicKey, sig: &Signature) -> bool {
    let secp = Secp256k1::<All>::new();
    let digest = sha256::Hash::hash(content);
    let message = Message::from_digest(digest.to_byte_array());
    secp.verify_ecdsa(message, sig, public_key).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_creation() {
        let keypair = Keypair::new();
        // 将私钥转换为字节数组进行检查
        let secret_bytes = keypair.secret_key.secret_bytes();
        assert!(!secret_bytes.iter().all(|&x| x == 0));
    }

    #[test]
    fn test_keypair_from_secret() {
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::from_sk(keypair1.secret_key);
        assert_eq!(keypair1.public_key, keypair2.public_key);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = Keypair::new();
        let message = b"Hello, world!";
        let signature = sign(&keypair, message);
        assert!(verify(message, &keypair.public_key, &signature));
    }

    #[test]
    fn test_verify_invalid_signature() {
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();
        let message = b"Hello, world!";
        let signature = sign(&keypair1, message);
        assert!(!verify(message, &keypair2.public_key, &signature));
    }

    #[test]
    fn test_verify_modified_message() {
        let keypair = Keypair::new();
        let message = b"Hello, world!";
        let signature = sign(&keypair, message);
        assert!(!verify(
            b"Modified message",
            &keypair.public_key,
            &signature
        ));
    }

    #[test]
    fn test_get_public_key() {
        let keypair = Keypair::new();
        let public_key = keypair.get_public_key();
        println!("{:?}", public_key);
        println!("{:?}", public_key.len());
        // assert_eq!(public_key.len(), 64);
    }

    #[test]
    fn test_get_secret_key() {
        let keypair = Keypair::new();
        let secret_key = keypair.get_secret_key();
        println!("{:?}", secret_key);
        println!("{:?}", secret_key.len());
        assert_eq!(secret_key.len(), 64);
    }

    #[test]
    fn test_temp() {
        let keypair = Keypair::new();
        let secret_key = keypair.get_secret_key();
        let public_key = keypair.get_public_key();
        println!("secret_key:{:?}", secret_key);
        println!("public_key:{:?}", public_key);

        let sig = sign(&keypair, b"Hello,world!");
        let ok: bool = verify(b"Hello,world!", &keypair.public_key, &sig);
        assert!(ok);
        println!("sig: {:?}", hex::encode(sig.serialize_compact()));
        println!("ok: {:?}", ok);
    }

    #[test]
    fn test_sk2pk() {
        let keypair = Keypair::from_sk_hex(
            "72242708cbb6ee199d03e06aa7e419c0247618844da0ef1a587f7f145eb1c7ba",
        );
        let secret_key = keypair.get_secret_key();
        let public_key = keypair.get_public_key();
        println!("secret_key:{:?}", secret_key);
        println!("public_key:{:?}", public_key);
        assert_eq!(
            secret_key,
            "72242708cbb6ee199d03e06aa7e419c0247618844da0ef1a587f7f145eb1c7ba"
        );
        assert_eq!(
            public_key,
            "03de5983f0ef2eb9e4af1268b826b900bdd672c251d5af7523dcd10b6eac5d5e57"
        );

        let sig = sign(&keypair, b"Hello, world!");
        let ok = verify(b"Hello, world!", &keypair.public_key, &sig);
        // println!("sig: {:?}", hex::decode(sig.serialize_compact()).unwrap());
        println!("ok: {:?}", ok);
    }

    #[test]
    fn test_bitcoin_address_generation() {
        // 使用已知的私钥生成密钥对
        let keypair = Keypair::from_sk_hex(
            "72242708cbb6ee199d03e06aa7e419c0247618844da0ef1a587f7f145eb1c7ba",
        );

        // 生成比特币地址
        let address = keypair.to_address();

        println!("Bitcoin Address: {}", address);
        assert_eq!(address, "1G1fWxQ6sMiKhSk3eoWwQijTMahjzcS1xG".to_string());

        // 验证地址格式（比特币地址通常以1开头，长度在26-35个字符之间）
        assert!(address.as_str().starts_with("1"));
        assert!(address.len() >= 26 && address.len() <= 35);
    }
}
