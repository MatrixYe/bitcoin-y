// 全局共识常量。

/// 公钥地址版本号，主网为 `0x00`。
pub const PUBKEY_VERSION: u8 = 0x00;

/// 最大区块大小，当前实验实现保持为 1 MB。
pub const MAX_BLOCK_SIZE: usize = 1024 * 1024;

/// 1 BTC = 100,000,000 聪。
pub const COIN: u64 = 100_000_000;

/// coinbase 输出需要 100 个区块成熟。
pub const COINBASE_MATURITY: usize = 100;

/// 当前实验链的 coinbase 奖励。
pub const COINBASE_REWARD: u64 = 1_000_000;
