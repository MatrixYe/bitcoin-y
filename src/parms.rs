//! @Name: parms
//!
//! @Date: 2026/7/18 08:42
//!
//! @Author: Matrix.Ye
//!
//! @Description: 自定义链运行的基本参数

use crate::uint256::Uint256;

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
    pub pow_limit: Uint256,
    pub target_spacing: u32,
    pub target_timespan: u32,
    // 初始区块补贴
    pub subsidy_initial: u64,
    // 区块补贴半衰期
    pub subsidy_halving_interval: u64,
}

impl ChainParams {
    pub const TEST: Self = Self::test();
    const fn test() -> Self {
        Self {
            network: Network::Test,
            pow_limit: Uint256::MAX,
            target_spacing: 0,
            target_timespan: 0,
            subsidy_initial: 50 * 100_000_000,
            subsidy_halving_interval: 210000,
        }
    }
}
