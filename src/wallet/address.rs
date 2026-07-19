use crate::hash::{hash160, sha256d};
use crate::parms::Network;
use crate::wallet::key::PubKey;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// @Name: address
///
/// @Date: 2026/7/6 04:13
///
/// @Author: Matrix.Ye
///
/// @Description: 最小 P2PKH 地址实现。地址只是展示/输入格式，钱包内部仍应优先使用公钥和公钥哈希。

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AddressError {
    // 无效的base58
    #[error("invalid base58 address")]
    InvalidBase58,

    // 地址负载长度错误，预期25
    #[error("invalid address payload length: expected 25, got {0}")]
    InvalidLength(usize),

    // 检验码失效
    #[error("invalid address checksum")]
    InvalidChecksum,

    // 不支持的网络版本
    #[error("unsupported address version: {0:#x}")]
    UnsupportedVersion(u8),
}

/// 公钥哈希 PubKeyHash，固定20字节
///
///
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PubKeyHash(pub [u8; 20]);

/// 地址 Address
///
/// 地址包含两个信息，网络类型和公钥哈希
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address {
    network: Network,
    pubkey_hash: PubKeyHash,
}

impl PubKeyHash {
    pub fn from_pubkey(pubkey: &PubKey, compress: bool) -> Self {
        PubKeyHash(hash160(&pubkey.serailaze(compress).as_bytes()))
    }

    pub fn as_bytes(&self) -> [u8; 20] {
        self.0
    }
}

impl Address {
    /// 使用公钥生成 P2PKH 地址。
    pub fn from_pk(pubkey: PubKey, network: Network, compress: bool) -> Self {
        Self {
            network,
            pubkey_hash: PubKeyHash::from_pubkey(&pubkey, compress),
        }
    }

    pub const fn from_pkh(pubkey_hash: [u8; 20], network: Network) -> Self {
        Self {
            network,
            pubkey_hash: PubKeyHash(pubkey_hash),
        }
    }

    pub const fn network(&self) -> Network {
        self.network
    }

    pub const fn pubkey_hash(&self) -> [u8; 20] {
        self.pubkey_hash.0
    }

    /// 编码为 Base58Check：`version || pubkey_hash || checksum`。
    pub fn to_base58(self) -> String {
        let mut payload = Vec::with_capacity(25);
        payload.push(self.network.to_p2pkh_prefix()); // 网络信息(1字节)
        payload.extend_from_slice(&self.pubkey_hash.0); // 公钥哈希(20字节)
        payload.extend_from_slice(&cal_checksum(&payload)); // 校验码(4字节)
        bs58::encode(payload).into_string() // base58编码
    }

    /// 从 Base58Check 解析 P2PKH 地址。
    pub fn from_base58(s: &str) -> Result<Self, AddressError> {
        // 序列化
        let payload = bs58::decode(s)
            .into_vec()
            .map_err(|_| AddressError::InvalidBase58)?;

        // 长度25字节
        if payload.len() != 25 {
            return Err(AddressError::InvalidLength(payload.len()));
        }
        // 网络标识
        let network = payload[0];
        // 数据段(网络标识+公钥哈希)
        let data = &payload[..21];
        // 校验码
        let actual_checksum = &payload[21..];
        if cal_checksum(data) != actual_checksum {
            return Err(AddressError::InvalidChecksum);
        }
        // 网络版本
        let network = Network::from_p2pkh_prefix(network)
            .ok_or(AddressError::UnsupportedVersion(payload[0]))?;

        // 公钥哈希
        let mut pubkey_hash = [0u8; 20];
        pubkey_hash.copy_from_slice(&payload[1..21]);

        Ok(Self::from_pkh(pubkey_hash, network))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl FromStr for Address {
    type Err = AddressError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_base58(value)
    }
}

/// 计算校验码
fn cal_checksum(data: &[u8]) -> [u8; 4] {
    let hash = sha256d(data); // 双重哈希计算
    // hash[..4].try_into().unwrap(); // 尽量减少unwrap的使用
    [hash[0], hash[1], hash[2], hash[3]] // 取计算后的前4个字节作为校验码
}

pub fn check_address(s: &str) -> bool {
    if let Ok(payload) = bs58::decode(s).into_vec() {
        if payload.len() != 25 {
            return false;
        }
        let network = &payload[0];
        // let pbhash = &payload[1..21];
        let data = &payload[..21];
        let actual_checksum = &payload[21..];
        if cal_checksum(data) != actual_checksum {
            return false;
        }
        if Network::is_illegal_prefix(network) {
            return false;
        }
        true
    } else {
        false
    }
}
