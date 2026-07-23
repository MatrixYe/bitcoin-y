// 全局共识常量。

/// 公钥地址版本号，主网为 `0x00`。
pub const PUBKEY_VERSION: u8 = 0x00;

/// 共识/接收区块时的最大大小；
pub const MAX_BLOCK_SIZE: usize = 1000000;
/// 本节点挖矿时默认生成区块的大小上限。
pub const MAX_BLOCK_SIZE_GEN: usize = MAX_BLOCK_SIZE / 2;


/// 1 BTC = 100,000,000 聪。
pub const COIN: u64 = 100_000_000;
/// 区块补贴初始值 50btc
pub const SUBSIDY_ORIGINAL: u64 = 50 * COIN;

/// 区块补贴的半衰期4年， $$4*365*24*6=210,240$$
pub const SUBSIDY_HALF_LIFE: u32 = 210000;

/// coinbase 输出需要 100 个区块成熟。
pub const COINBASE_MATURITY: usize = 100;

/// 当前实验链的 coinbase 奖励。
pub const COINBASE_REWARD: u64 = 1_000_000;
