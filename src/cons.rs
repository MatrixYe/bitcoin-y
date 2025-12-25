/**
 * 常量定义
 */

/// 公钥版本号 0x00 主网
const PUBKEY_VERSION: u8 = 0x00;

/// 最大区块大小 1MB
const MAX_BLOCK_SIZE: usize = 1024 * 1024;

/// 比特币单位 1比特币 = 100,000,000 聪
const COIN: u64 = 100_000_000;

/// 比特币挖矿奖励确认数 100 个区块,也不知道中本聪咋想的，100个区块确认后才会被认为是有效交易
const COINBASE_MATURITY: usize = 100;
