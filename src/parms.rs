//! @Name: parms
//!
//! @Date: 2026/7/18 08:42
//!
//! @Author: Matrix.Ye
//!
//! @Description: 自定义链运行的基本参数

use crate::uint256::Uint256;
use thiserror::Error;

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
    // 网络参数
    pub network: Network,

    // 挖矿需要的目标值最大值，即所需难度的最小值。
    pub pow_target_limit: Uint256,

    // 创世区块设定的目标值
    pub pow_target_genesis: Uint256,

    // 目标出块间隔，默认10分钟,10 * 60
    pub target_spacing: u32,

    // 目标调整周期，默认两周一次，14 * 24 * 60 * 60
    pub target_timespan: u32,

    // 初始区块补贴，默认50btc
    pub subsidy_initial: u64,

    // 区块补贴半衰期，默认4年，大约 4*365*24*6=210240 个区块
    pub subsidy_halving_interval: u64,
}
#[derive(Debug, Clone, PartialEq, Error)]
pub enum ChainParamsError {
    #[error("invalid Parameters: {param}, must be greater than zero")]
    InvalidParameters { param: String },

    #[error("targetspacing must be smaller than timespan,but actual: {actual_target_spacing} > {actual_target_timespan}"
    )]
    TimeSpacingTooBig {
        actual_target_spacing: u32,
        actual_target_timespan: u32,
    },

    #[error("target_timespan % target_spacing must be zero,but actual: {actual_target_spacing},{actual_target_timespan}"
    )]
    TimeNotMatch {
        actual_target_spacing: u32,
        actual_target_timespan: u32,
    },
}
impl ChainParams {
    pub const TEST: Self = Self::new_test();
    pub const MAIN: Self = Self::new_main();
    const fn new_test() -> Self {
        Self {
            network: Network::Test,
            pow_target_limit: Uint256::LIMIT,
            pow_target_genesis: Uint256::GENESIS,
            target_spacing: 2 * 60,
            target_timespan: 1 * 60 * 60,
            subsidy_initial: 50 * 100_000_000,
            subsidy_halving_interval: 210000,
        }
    }
    const fn new_main() -> Self {
        Self {
            network: Network::Main,
            pow_target_limit: Uint256::LIMIT,
            pow_target_genesis: Uint256::GENESIS,
            target_spacing: 10 * 60, // 10分钟
            target_timespan: 14 * 24 * 60 * 60, // 2周=14天
            subsidy_initial: 50 * 100_000_000,
            subsidy_halving_interval: 210000,
        }
    }

    // 链运行参数检测
    // pub fn check(&self) -> bool {
    //     self.target_spacing != 0
    //         && self.target_timespan != 0
    //         && self.subsidy_initial != 0
    //         && self.subsidy_halving_interval != 0
    //         && !self.pow_target_limit.is_zero()
    //         && self.target_spacing < self.target_timespan
    //         && self.target_timespan % self.target_spacing == 0
    // }

    pub fn check(&self) -> Result<bool, ChainParamsError> {
        if self.pow_target_limit == Uint256::ZERO {
            return Err(ChainParamsError::InvalidParameters { param: "pow_target_limit".to_string() });
        }
        if self.pow_target_genesis == Uint256::ZERO {
            return Err(ChainParamsError::InvalidParameters { param: "pow_target_genesis".to_string() });
        }
        if self.target_spacing == 0 {
            return Err(ChainParamsError::InvalidParameters { param: "target_spacing".to_string() });
        }
        if self.target_timespan == 0 {
            return Err(ChainParamsError::InvalidParameters { param: "target_timespan".to_string() });
        }
        if self.subsidy_initial == 0 {
            return Err(ChainParamsError::InvalidParameters { param: "subsidy_initial".to_string() });
        }
        if self.subsidy_halving_interval == 0 {
            return Err(ChainParamsError::InvalidParameters { param: "subsidy_halving_interval".to_string() });
        }
        if self.target_spacing >= self.target_timespan {
            return Err(ChainParamsError::TimeSpacingTooBig {
                actual_target_spacing: self.target_spacing,
                actual_target_timespan: self.target_timespan,
            });
        }
        if self.target_timespan % self.target_spacing != 0 {
            return Err(ChainParamsError::TimeNotMatch {
                actual_target_spacing: self.target_spacing,
                actual_target_timespan: self.target_timespan,
            });
        }

        Ok(true)
    }
}
