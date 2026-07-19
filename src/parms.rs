//! @Name: parms
//!
//! @Date: 2026/7/18 08:42
//!
//! @Author: Matrix.Ye
//!
//! @Description: 自定义链运行的基本参数

use crate::bignum::BigNum;

/// 网络类型 Network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Main,
    Test,
}
impl Network {
    pub const fn to_p2pkh_prefix(self) -> u8 {
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

    pub fn is_legal_prefix(p: &u8) -> bool {
        Self::from_p2pkh_prefix(*p).is_some()
    }

    pub fn is_illegal_prefix(p: &u8) -> bool {
        Self::from_p2pkh_prefix(*p).is_none()
    }
}

/// 链运行需要的自定义参数
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainParams {
    pub network: Network,
    // pub genesis_block: Block,
    pub pow_limit: u32,
    // 目标出块间隔，默认10分钟最佳
    pub target_spacing: u32,
    // 目标调整周期，蛛网两周一次
    pub target_timespan: u32,
    // 初始区块补贴
    pub subsidy_initial: u64,
    // 区块补贴半衰期
    pub subsidy_halving_interval: u64,
}

impl ChainParams {
    pub const TEST: Self = Self::new_test();
    pub const MAIN: Self = Self::new_main();
    const fn new_test() -> Self {
        Self {
            network: Network::Test,
            pow_limit: 0x1d00ffff,
            target_spacing: 2 * 60,
            target_timespan: 1 * 60 * 60,
            subsidy_initial: 50 * 100_000_000,
            subsidy_halving_interval: 210000,
        }
    }
    const fn new_main() -> Self {
        Self {
            network: Network::Test,
            pow_limit: 0x1d00ffff,
            target_spacing: 10 * 60, // 10分钟
            target_timespan: 14 * 24 * 60 * 60, // 2周=14天
            subsidy_initial: 50 * 100_000_000,
            subsidy_halving_interval: 210000,
        }
    }

    // 链运行参数检测
    pub fn check(&self) -> bool {
        let x = BigNum::from_i32(0x1d00ffff);
        self.target_spacing != 0
            && self.target_timespan != 0
            && self.subsidy_initial != 0
            && self.subsidy_halving_interval != 0
            && self.pow_limit != 0
            && self.target_spacing < self.target_timespan
            && self.target_timespan % self.target_spacing == 0
    }
}
