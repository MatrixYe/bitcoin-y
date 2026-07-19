// 全局共识常量。

/// 公钥地址版本号，主网为 `0x00`。
pub const PUBKEY_VERSION: u8 = 0x00;

/// 最大区块大小，当前实验实现保持为 1 MB。
pub const MAX_BLOCK_SIZE: usize = 1024 * 1024;

/// 1 BTC = 100,000,000 聪。
pub const COIN: u64 = 100_000_000;
//static const int64 COIN = 100000000;
// Max=2100*10000*10^8=21,000,000 * 10^8=2*10^7 * 1 * 10^8 =2 * 10^15

/// 区块补贴初始值 50btc
pub const SUBSIDY_ORIGINAL: u64 = 50 * COIN;

/// 区块补贴的半衰期4年， $$4*365*24*6=210,240$$
pub const SUBSIDY_HALF_LIFE: u32 = 210000;

/// coinbase 输出需要 100 个区块成熟。
pub const COINBASE_MATURITY: usize = 100;

/// 当前实验链的 coinbase 奖励。
pub const COINBASE_REWARD: u64 = 1_000_000;
