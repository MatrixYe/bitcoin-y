//! 网络、共识和节点运行参数。
//!
//! [`Params`] 是节点启动后共享的只读参数快照。它不保存链状态，也不负责
//! 修改配置；调用方可以通过 `Arc<Params>` 在多个模块之间共享同一份参数。

use crate::uint256::Uint256;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;


const DEFAULT_DATA_DIR: &str = "data";
const DEFAULT_MAX_MEMPOOL_BYTES: usize = 100 * 1024 * 1024;
const DEFAULT_MAX_BLOCK_SIZE_GEN: usize = 1_000_000 / 2;
const DEFAULT_MAX_PEERS: usize = 8;

/// 节点使用的一组完整参数。
///
/// 三类参数保持为顶层字段，避免把网络参数和节点策略再包进共识参数：
///
/// - `consensus` 决定交易和区块是否合法
/// - `network` 决定节点使用哪个网络身份和协议参数
/// - `config` 决定本节点的本地运行策略
///
/// 参数初始化后应作为只读值共享。修改共识参数等同于选择另一条链，绝对不能在节点运行期间通过共享引用悄然改变。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Params {
    pub consensus: ConsensusParams,
    pub network: NetworkParams,
    pub config: Config,
}

/// 参数初始化或共享前的不变量检查失败。
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid parameter {field}: {reason}")]
pub struct ParamsError {
    pub field: &'static str,
    pub reason: &'static str,
}

impl Params {
    /// 创建 by 网络
    pub fn from_network(network: Network) -> Self {
        Self {
            consensus: ConsensusParams::from_network(network),
            network: NetworkParams::from_network(network),
            config: Config::from_network(network),
        }
    }

    /// 参数检测
    pub fn validate(&self) -> Result<(), ParamsError> {
        self.consensus.validate()?;
        self.network.validate()?;
        self.config.validate()?;

        if self.config.max_block_size_gen > self.consensus.max_block_size {
            return Err(ParamsError { field: "max_block_size_gen", reason: "must be greater than zero and no greater than the consensus limit" });
        }
        Ok(())
    }

    /// 校验后移交参数所有权，供各模块通过共享引用读取。
    ///
    /// 预设可以暂时不包含创世块哈希；在需要验证创世块的阶段，应在调用本方法
    /// 前填入实际的 `genesis_hash`。共享期间不要使用 `Arc::make_mut` 或内部
    /// 可变性修改参数。
    pub fn into_shared(self) -> Result<Arc<Self>, ParamsError> {
        self.validate()?;
        Ok(Arc::new(self))
    }
}

impl Default for Params {
    fn default() -> Self {
        Self::from_network(Network::Main)
    }
}

/// 决定交易和区块有效性的共识参数
///
/// 这些字段属于链定义的一部分。它们可以因网络不同而不同，但对某个已经选择的网络必须保持不变。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusParams {
    /// 一个 BTC 包含的最小货币单位数量。
    pub coin: u64,
    /// 单笔交易和 UTXO 金额检查使用的总货币上限。
    pub max_money: u64,
    /// 接收区块时允许的最大序列化大小。
    pub max_block_size: usize,
    /// 区块内允许的最大 sigop 数量。
    pub max_block_sigops: usize,
    /// 实验链创世区块的实际哈希；未定义时不能启动节点。
    pub genesis_hash: Option<Uint256>,
    /// 创世区块使用的 PoW 目标值，与创世区块哈希不同。
    pub pow_target_genesis: Uint256,
    /// 允许的最大 PoW target，也就是最小难度。
    pub pow_target_limit: Uint256,
    /// 目标出块间隔，单位为秒。
    pub target_spacing: u32,
    /// 难度调整周期的目标时间跨度，单位为秒。
    pub target_timespan: u32,
    /// 初始区块补贴，单位为最小货币单位。
    pub subsidy_initial: u64,
    /// 补贴减半间隔，单位为区块数。
    pub subsidy_halving_interval: u32,
    /// Coinbase 输出可以被花费前需要的确认深度。
    pub coinbase_maturity: u32,
}

impl ConsensusParams {
    /// 创建指定网络的共识参数。
    pub fn from_network(network: Network) -> Self {
        match network {
            Network::Main => {
                Self {
                    coin: 100_000_000,
                    max_money: 21_000_000 * 100_000_000,
                    max_block_size: 1_000_000,
                    max_block_sigops: 1_000_000 / 50,
                    genesis_hash: None,
                    pow_target_genesis: Uint256::GENESIS,
                    pow_target_limit: Uint256::LIMIT,
                    target_spacing: 10 * 60,
                    target_timespan: 14 * 24 * 60 * 60,
                    subsidy_initial: 50 * 100_000_000,
                    subsidy_halving_interval: 210_000,
                    coinbase_maturity: 6,
                }
            }
            Network::Test => {
                Self {
                    coin: 100_000_000,
                    max_money: 21_000_000 * 100_000_000,
                    max_block_size: 1_000_000,
                    max_block_sigops: 1_000_000 / 50,
                    genesis_hash: None,
                    pow_target_genesis: Uint256::GENESIS,
                    pow_target_limit: Uint256::LIMIT,
                    target_spacing: 10 * 60,
                    target_timespan: 14 * 24 * 60 * 60,
                    subsidy_initial: 50 * 100_000_000,
                    subsidy_halving_interval: 210_000,
                    coinbase_maturity: 6,
                }
            }
        }
    }

    /// 校验预设或通过字段赋值调整后的共识参数。
    pub fn validate(&self) -> Result<(), ParamsError> {
        for (field, value) in [
            ("coin", self.coin),
            ("max_money", self.max_money),
            ("target_spacing", u64::from(self.target_spacing)),
            ("subsidy_halving_interval", u64::from(self.subsidy_halving_interval)),
        ] {
            if value == 0 {
                return Err(ParamsError { field, reason: "must be greater than zero" });
            }
        }
        if self.target_timespan < 4 || self.target_timespan < self.target_spacing || self.target_timespan % self.target_spacing != 0 {
            return Err(ParamsError { field: "target_timespan", reason: "must be at least four seconds and a positive multiple of target_spacing" });
        }
        if self.max_money < self.coin || self.subsidy_initial > self.max_money {
            return Err(ParamsError { field: "max_money", reason: "must cover one coin and the initial subsidy" });
        }
        if self.max_block_size == 0 || self.max_block_sigops == 0 {
            return Err(ParamsError { field: "block_limits", reason: "block size and sigop limit must be greater than zero" });
        }
        if self.pow_target_genesis.is_zero() || self.pow_target_limit.is_zero() || self.pow_target_genesis > self.pow_target_limit {
            return Err(ParamsError { field: "pow_target_genesis", reason: "must be positive and no greater than pow_target_limit" });
        }
        if self.genesis_hash == Some(Uint256::ZERO) {
            return Err(ParamsError { field: "genesis_hash", reason: "must not use zero as a placeholder" });
        }
        Ok(())
    }
}

impl Default for ConsensusParams {
    fn default() -> Self {
        Self::from_network(Network::Main)
    }
}

/// bitcoin-y 的实验网络预设，不兼容 Bitcoin 主网或测试网
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Main,
    Test,
}

impl Network {
    /// 返回该网络的传统 P2PKH 地址版本字节
    pub const fn to_p2pkh_prefix(self) -> u8 {
        match self {
            Self::Main => 0x00,
            Self::Test => 0x6f,
        }
    }

    /// 根据传统 P2PKH 地址版本字节识别网络。
    pub const fn from_p2pkh_prefix(prefix: u8) -> Option<Self> {
        match prefix {
            0x00 => Some(Self::Main),
            0x6f => Some(Self::Test),
            _ => None,
        }
    }

    /// 判断地址版本字节是否属于支持的网络
    pub const fn is_legal_prefix(prefix: &u8) -> bool {
        Self::from_p2pkh_prefix(*prefix).is_some()
    }

    /// 判断地址版本字节是否不属于任何支持的网络
    pub const fn is_illegal_prefix(prefix: &u8) -> bool {
        !Self::is_legal_prefix(prefix)
    }
}

/// 网络协议和地址编码参数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkParams {
    /// 选择的实验网络。
    pub network: Network,
    /// bitcoin-y 自有的消息标识，避免与 Bitcoin 网络混用
    pub message_magic: [u8; 4],
    /// 网络的默认端口，实际监听端口由 Config 指定
    pub default_port: u16,
    /// 传统 P2PKH 地址版本字节，不单独证明链身份
    pub p2pkh_prefix: u8,
}

impl NetworkParams {
    /// 创建指定网络的网络参数。
    pub fn from_network(network: Network) -> Self {
        let (message_magic, default_port) = match network {
            Network::Main => (*b"BTYM", 8848),
            Network::Test => (*b"BTYT", 18848),
        };

        Self {
            network,
            message_magic,
            default_port,
            p2pkh_prefix: network.to_p2pkh_prefix(),
        }
    }

    pub fn validate(&self) -> Result<(), ParamsError> {
        let expected_prefix = self.network.to_p2pkh_prefix();
        if self.p2pkh_prefix != expected_prefix {
            return Err(ParamsError { field: "p2pkh_prefix", reason: "must match the selected network" });
        }
        if self.message_magic == [0; 4] {
            return Err(ParamsError { field: "message_magic", reason: "must not be all zeroes" });
        }
        if self.default_port == 0 {
            return Err(ParamsError { field: "default_port", reason: "must be greater than zero" });
        }
        Ok(())
    }
}

impl Default for NetworkParams {
    fn default() -> Self {
        Self::from_network(Network::Main)
    }
}

/// 只影响本节点行为的本地运行配置
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// 本网络的数据目录。相对路径基于进程工作目录，不展开 `~`，不自动创建。
    pub data_dir: PathBuf,
    /// 实际监听端口；0 表示由系统分配端口。
    pub listen_port: u16,
    /// 内存池允许使用的最大字节数。
    pub max_mempool_bytes: usize,
    /// 矿工主动生成区块时采用的大小上限。
    pub max_block_size_gen: usize,
    /// 是否监听入站连接。
    pub listen: bool,
    /// 允许同时维护的最大 peer 数量。
    pub max_peers: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self::from_network(Network::Main)
    }
}

impl Config {
    /// 为所选网络创建本地默认配置；切换网络时应重新创建整份 Params
    pub fn from_network(network: Network) -> Self {
        let directory = match network {
            Network::Main => "main",
            Network::Test => "test",
        };
        Self {
            data_dir: PathBuf::from(DEFAULT_DATA_DIR).join(directory),
            listen_port: NetworkParams::from_network(network).default_port,
            max_mempool_bytes: DEFAULT_MAX_MEMPOOL_BYTES,
            max_block_size_gen: DEFAULT_MAX_BLOCK_SIZE_GEN,
            listen: true,
            max_peers: DEFAULT_MAX_PEERS,
        }
    }

    pub fn validate(&self) -> Result<(), ParamsError> {
        if self.data_dir.as_os_str().is_empty() {
            return Err(ParamsError { field: "data_dir", reason: "must not be empty" });
        }
        if self.max_mempool_bytes == 0 {
            return Err(ParamsError { field: "max_mempool_bytes", reason: "must be greater than zero" });
        }
        if self.max_block_size_gen == 0 {
            return Err(ParamsError { field: "max_block_size_gen", reason: "must be greater than zero and no greater than the consensus limit" });
        }
        if self.max_peers == 0 {
            return Err(ParamsError { field: "max_peers", reason: "must be greater than zero" });
        }

        Ok(())
    }
}
