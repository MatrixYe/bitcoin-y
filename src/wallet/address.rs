use crate::hash::sha256d;
use crate::wallet::key::{PubKey, hash160_pubkey};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Main,
    Test,
}

impl Network {
    pub const fn p2pkh_prefix(self) -> u8 {
        match self {
            Self::Main => 0x00,
            Self::Test => 0x6f,
        }
    }

    pub const fn from_p2pkh_prefix(prefix: u8) -> Option<Self> {
        match prefix {
            0x00 => Some(Self::Main),
            0x6f => Some(Self::Test),
            _ => None,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AddressError {
    #[error("invalid base58 address")]
    InvalidBase58,

    #[error("invalid address payload length: expected 25, got {0}")]
    InvalidLength(usize),

    #[error("invalid address checksum")]
    InvalidChecksum,

    #[error("unsupported address version: {0:#x}")]
    UnsupportedVersion(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PubKeyHash(pub [u8; 20]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address {
    network: Network,
    pubkey_hash: PubKeyHash,
}

impl Address {
    /// 使用公钥生成 P2PKH 地址。
    pub fn p2pkh(pubkey: PubKey, network: Network) -> Self {
        Self {
            network,
            pubkey_hash: PubKeyHash(hash160_pubkey(pubkey)),
        }
    }

    pub const fn new_p2pkh(pubkey_hash: [u8; 20], network: Network) -> Self {
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
        payload.push(self.network.p2pkh_prefix());
        payload.extend_from_slice(&self.pubkey_hash.0);
        payload.extend_from_slice(&checksum(&payload));
        bs58::encode(payload).into_string()
    }

    /// 从 Base58Check 解析 P2PKH 地址。
    pub fn from_base58(value: &str) -> Result<Self, AddressError> {
        let payload = bs58::decode(value)
            .into_vec()
            .map_err(|_| AddressError::InvalidBase58)?;

        if payload.len() != 25 {
            return Err(AddressError::InvalidLength(payload.len()));
        }

        let data = &payload[..21];
        let actual_checksum = &payload[21..];
        if checksum(data) != actual_checksum {
            return Err(AddressError::InvalidChecksum);
        }

        let network = Network::from_p2pkh_prefix(payload[0])
            .ok_or(AddressError::UnsupportedVersion(payload[0]))?;
        let mut pubkey_hash = [0u8; 20];
        pubkey_hash.copy_from_slice(&payload[1..21]);

        Ok(Self::new_p2pkh(pubkey_hash, network))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base58())
    }
}

impl FromStr for Address {
    type Err = AddressError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_base58(value)
    }
}

fn checksum(data: &[u8]) -> [u8; 4] {
    let hash = sha256d(data);
    [hash[0], hash[1], hash[2], hash[3]]
}
