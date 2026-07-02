use crate::bignum::BigNum;
use crate::block::BlockHeader;
use crate::uint256::Uint256;
use std::collections::HashMap;
use thiserror::Error;

/// @Name: chain
///
/// @Date: 2026/6/18 16:14
///
/// @Author: Matrix.Ye
///
/// @Description:
/// 区块树索引。这里保存的是“区块头 + 链关系 + 累计工作量”，不是完整区块体。
///
/// 原版 `CBlockIndex` 通过裸指针 `pprev/pnext` 连接节点。Rust 中更适合用区块哈希作为稳定 ID，
/// 再由 `BlockTree` 统一持有 `HashMap<Uint256, BlockIndex>`，避免自引用结构和生命周期复杂度（主要是现在我的rust水平还不够）
///
/// `prev` 表示该区块头声明的父区块；`next` 只表示当前最佳链上的下一块，不代表所有子分支。
/// 所有分叉子节点由 `BlockTree.children` 记录。
///
///

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChainError {
    // 重复的block
    #[error("duplicate block index: {hash}")]
    DuplicateBlock { hash: Uint256 },

    // 没有前序的block
    #[error("unknown previous block: {prev}")]
    UnknownPrevBlock { prev: Uint256 },

    // 本地找不到block
    #[error("unknown block index: {hash}")]
    UnknownBlock { hash: Uint256 },

    // 创世块已经存在
    #[error("genesis block already exists: {hash}")]
    GenesisAlreadyExists { hash: Uint256 },
}

/// 后续存储层需要实现的最小区块树持久化接口。
///
/// 当前挖矿流程优先以内存为主，所以这里先只定义 trait，不绑定 SQLite、文件或其他具体存储。
pub trait ChainStore {
    type Error;

    fn load_block_indexes(&self) -> Result<Vec<BlockIndex>, Self::Error>;
    fn load_best_hash(&self) -> Result<Option<Uint256>, Self::Error>;
    fn write_block_index(&mut self, index: &BlockIndex) -> Result<(), Self::Error>;
    fn write_best_hash(&mut self, hash: Uint256) -> Result<(), Self::Error>;
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockIndex {
    hash: Uint256,
    pub prev: Option<Uint256>,
    pub next: Option<Uint256>,
    pub height: u32,
    pub chain_work: BigNum,

    // block header
    pub version: i32,
    pub prev_block: Uint256,
    pub merkle_root: Uint256,
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

#[derive(Debug, Clone, Default)]
pub struct BlockTree {
    /// 原版 `mapBlockIndex`：所有已知区块索引，key 是区块哈希。
    ///
    /// 这是区块树的主索引。任何区块节点都应该先能通过 hash 在这里找到。
    indexes: HashMap<Uint256, BlockIndex>,

    /// 所有子分支。原版没有单独保存这个表，主要靠 `pprev` 反查；Rust 中显式保存更方便。
    ///
    /// key 是父区块 hash，value 是所有直接子区块 hash。它表示完整分叉关系，不只表示最佳链。
    children: HashMap<Uint256, Vec<Uint256>>,

    /// 原版 `pindexGenesisBlock` 的 hash 版本。
    ///
    /// 创世块只有一个，单独记录可以避免每次都从高度 0 或 prev=None 反查。
    genesis: Option<Uint256>,

    /// 原版 `hashBestChain` / `pindexBest` 的 hash 版本。
    ///
    /// 这里保存当前最佳链的 tip hash，真正的节点数据仍然存放在 `indexes` 里。
    best_hash: Option<Uint256>,

    /// 原版 `nBestHeight`。
    ///
    /// 这是 `best` 对应区块的高度，作为缓存字段保存，避免频繁查 best index。
    best_height: Option<u32>,

    /// 原版 `bnBestChainWork`。
    ///
    /// 当前最佳链 tip 的累计工作量。链选择比较的是累计工作量，不是单纯高度。
    best_chain_work: BigNum,

    /// 原版 `bnBestInvalidWork`，当前先保存状态，后续接入无效链处理。
    ///
    /// 如果后续发现某条无效链的累计工作量很大，可以用这个字段辅助告警或拒绝相关分支。
    best_invalid_work: BigNum,

    /// 当前最佳链，`active_chain[height] = hash`。这是 `pnext` 的 Rust 化辅助索引。
    ///
    /// `BlockIndex.next` 只表示最佳链上的下一块；`active_chain` 则提供按高度快速查询主链块的能力。
    active_chain: Vec<Uint256>,
}

/// 计算当前区块的工作量
fn get_work_from_nbits(nbits: u32) -> BigNum {
    let a = BigNum::from_u32(1) << 256;
    let target = BigNum::set_compact(nbits);
    if target <= BigNum::ZERO {
        BigNum::ZERO
    } else {
        // a / (target + BigNum::from_u32(1))
        a / (target + 1u32)
    }
}

impl BlockIndex {
    pub fn new(header: &BlockHeader, prev_bi: Option<&BlockIndex>) -> Self {
        let hash = header.hash();
        let prev = prev_bi.map(|bi| bi.hash);
        let block_work = get_work_from_nbits(header.bits);
        let height = prev_bi.map_or(0, |x| x.height + 1);
        let chain_work = prev_bi.map_or(block_work.clone(), |x| x.chain_work.clone() + block_work.clone());

        Self {
            hash,
            prev,
            next: None,
            height,
            chain_work,
            version: header.version,
            prev_block: header.prev_block,
            merkle_root: header.merkle_root,
            time: header.time,
            bits: header.bits,
            nonce: header.nonce,
        }
    }

    /// 获取当前区块哈希
    pub fn hash(&self) -> Uint256 {
        self.hash
    }

    /// 获取当前块的工作量
    pub fn get_block_work(&self) -> BigNum {
        get_work_from_nbits(self.bits)
    }

    /// 获取区块链的累计工作量
    pub fn get_chain_work(&self) -> BigNum {
        self.chain_work.clone()
    }

    /// 判断是否是创世区块索引。
    pub fn is_genesis(&self) -> bool {
        self.prev.is_none()
    }

    /// 还原区块头。
    pub fn header(&self) -> BlockHeader {
        BlockHeader {
            version: self.version,
            prev_block: self.prev_block,
            merkle_root: self.merkle_root,
            time: self.time,
            bits: self.bits,
            nonce: self.nonce,
        }
    }

    /// 检测是否符合工作量
    pub fn check_work(&self) -> bool {
        let (target, negative, overflow) = Uint256::set_compact(self.bits);
        if negative || overflow || target == Uint256::ZERO {
            false
        } else {
            self.hash <= target
        }
    }
}

impl BlockTree {
    /// 创建一个空的内存区块树。
    pub fn new() -> Self {
        Self::default()
    }

    /// 从本地存储中恢复内存区块树。具体存储模块后续实现时可以直接调用这里。
    ///
    /// 恢复流程：
    /// 1. 去重，把所有 `BlockIndex` 放回 `tree.indexes`
    /// 2. 根据每个节点的 `prev` 重建 `tree.children`
    /// 3. 如果发现`BlockIndex.prev == None`，设置为创世区块
    /// 3. 如果存储层提供了 best，就用它；否则选择累计工作量最大的节点
    /// 4. 调用 `set_best_chain` 重建 active chain 和 `next` 字段
    pub fn from_indexes(db_indexes: Vec<BlockIndex>, db_best: Option<Uint256>) -> Result<Self, ChainError> {
        let mut tree = Self::new();

        for index in db_indexes {
            let hash = index.hash();
            // indexes
            if tree.indexes.contains_key(&hash) {
                return Err(ChainError::DuplicateBlock { hash });
            }
            // genesis
            if index.is_genesis() {
                tree.genesis = Some(index.hash());
            }
            tree.indexes.insert(hash, index);
            // childrens
            tree.children.entry(hash).or_default().push(hash);
        }
        // best
        let best = db_best.map_or(
            tree.indexes.values().max_by(|left, right| left.chain_work.cmp(&right.chain_work)).map(|x| x.hash),
            |x| Some(x));
        if let Some(hash) = best {
            tree.set_best_chain(hash)?;
        }
        Ok(tree)
    }

    /// 返回当前已知区块索引数量。
    pub fn len(&self) -> usize {
        self.indexes.len()
    }

    /// 判断区块树是否为空。
    pub fn is_empty(&self) -> bool {
        self.indexes.is_empty()
    }

    /// 判断某个区块 hash 是否已经存在于本地区块树中。
    pub fn contains(&self, hash: Uint256) -> bool {
        self.indexes.contains_key(&hash)
    }

    /// 通过区块 hash 获取对应的区块索引。
    pub fn get(&self, hash: Uint256) -> Option<&BlockIndex> {
        self.indexes.get(&hash)
    }

    /// 获取创世区块 hash。
    pub fn genesis_hash(&self) -> Option<Uint256> {
        self.genesis
    }

    /// 获取当前最佳链 tip 的 hash。
    pub fn best_hash(&self) -> Option<Uint256> {
        self.best_hash
    }

    /// 获取当前最佳链 tip 的区块索引。
    pub fn best_index(&self) -> Option<&BlockIndex> {
        self.best_hash.and_then(|hash| self.get(hash))
    }

    /// 获取当前最佳链高度。
    pub fn best_height(&self) -> Option<u32> {
        self.best_height
    }

    /// 获取当前最佳链累计工作量。
    pub fn best_chain_work(&self) -> &BigNum {
        &self.best_chain_work
    }

    /// 获取当前记录到的最大无效链工作量。
    pub fn best_invalid_work(&self) -> &BigNum {
        &self.best_invalid_work
    }

    /// 获取当前最佳链的 hash 列表。
    ///
    /// 返回值满足 `active_chain[height] = hash`。
    pub fn active_chain(&self) -> &[Uint256] {
        &self.active_chain
    }

    /// 按高度获取当前最佳链上的区块 hash。
    pub fn active_hash_at_height(&self, height: u32) -> Option<Uint256> {
        // self.active_chain.get(height as usize).clone()
        // 等价与 `self.active_chain.get(height as usize).map(|x| *x)`
        self.active_chain.get(height as usize).copied()
    }

    /// 获取某个区块的所有直接子区块。
    ///
    /// 这里返回的是完整区块树分叉子节点，不等同于 `BlockIndex.next`。
    pub fn children(&self, hash: Uint256) -> &[Uint256] {
        self.children.get(&hash).map_or(&[], |x| x.as_slice())
    }

    /// 添加创世区块索引。
    ///
    /// 创世区块没有父索引；添加后会同时成为当前最佳链。
    pub fn add_genesis(&mut self, header: &BlockHeader) -> Result<Uint256, ChainError> {
        if let Some(hash) = self.genesis {
            return Err(ChainError::GenesisAlreadyExists { hash });
        }
        let hash = self.insert_index(header, None)?;
        self.genesis = Some(hash);
        self.set_best_chain(hash)?;
        Ok(hash)
    }

    /// 添加一个普通区块头索引。
    ///
    /// 调用者应先完成区块头验证和 PoW 验证；这里负责维护区块树关系和最佳链选择。
    pub fn add_header(&mut self, header: &BlockHeader) -> Result<Uint256, ChainError> {
        let prev_hash = header.prev_block;
        let prev = self.indexes.get(&prev_hash).ok_or(ChainError::UnknownPrevBlock { prev: prev_hash })?.clone();
        let hash = self.insert_index(header, Some(&prev))?;
        let option = self.get(hash);
        let should_update_best = match self.best_index() {
            Some(best) => self.indexes[&hash].chain_work > best.chain_work,
            None => true,
        };
        if should_update_best {
            self.set_best_chain(hash)?;
        }

        Ok(hash)
    }

    /// 纯粹的插入一个区块索引节点，但不主动切换最佳链。
    ///
    /// 这是 `add_genesis` 和 `add_header` 的公共内部步骤：
    /// 创建 `BlockIndex`，写入主索引，并把它挂到父节点的 children 列表下。
    fn insert_index(&mut self, header: &BlockHeader, prev: Option<&BlockIndex>) -> Result<Uint256, ChainError> {
        let hash = header.hash();
        if self.contains(hash) {
            return Err(ChainError::DuplicateBlock { hash });
        }
        let index = BlockIndex::new(header, prev);
        if let Some(prev) = index.prev {
            self.children.entry(prev).or_default().push(hash);
        }
        self.indexes.insert(hash, index);
        Ok(hash)
    }

    /// 按累计工作量选择最佳链，并重建 active chain 与各节点的 `next` 字段。
    ///
    /// 实现：
    /// 1. 清空所有节点的 `next`，避免旧主链残留。
    /// 2. 从新的 tip 沿 `prev` 一直回溯到创世块，得到一条反向路径。
    /// 3. 反转路径得到从创世块到 tip 的 active chain。
    /// 4. 按 active chain 重新设置每个节点的 `next`。
    /// 5. 更新 best hash、高度、累计工作量和 active chain 缓存。
    pub fn set_best_chain(&mut self, tip: Uint256) -> Result<(), ChainError> {
        if !self.indexes.contains_key(&tip) {
            return Err(ChainError::UnknownBlock { hash: tip });
        }
        // 清空所有节点的`next`
        for index in self.indexes.values_mut() {
            index.next = None;
        }
        // 尝试构建最佳链路径
        let mut path = Vec::new();
        let mut current = Some(tip);
        while let Some(hash) = current {
            let index = self.indexes.get(&hash).ok_or(ChainError::UnknownBlock { hash })?;
            path.push(hash);
            current = index.prev;
        }
        path.reverse(); // 反转

        // 构建最佳链上的每个节点的`next`
        for window in path.windows(2) {
            let prev = window[0];
            let next = window[1];
            self.indexes.get_mut(&prev).ok_or(ChainError::UnknownBlock { hash: prev })?.next = Some(next);
        }

        let best_block_index = self.indexes.get(&tip).ok_or(ChainError::UnknownBlock { hash: tip })?;
        // 最重链当前哈希
        self.best_hash = Some(tip);
        // 最重链高度
        self.best_height = Some(best_block_index.height);
        // 最重链的累计工作量
        self.best_chain_work = best_block_index.chain_work.clone();
        // 当前最重链哈希路径
        self.active_chain = path;
        Ok(())
    }

    /// 判断某个区块是否位于当前最佳链上。
    ///
    /// 通过节点高度到 `active_chain` 中做一次定位，比从 tip 一路回溯更直接。
    pub fn is_in_best_chain(&self, hash: Uint256) -> bool {

        // 先判断Block在不在
        let Some(index) = self.get(hash) else {
            return false;
        };
        // 再判断在不在最佳链上
        self.active_hash_at_height(index.height) == Some(hash)
    }

    /// 查找两个区块所在分支的共同祖先。
    ///
    /// 实现思路：
    /// 1. 先把较高的区块沿 `prev` 回退到同一高度。
    /// 2. 然后两个分支同时向前回退。
    /// 3. 第一个 hash 相同的节点就是 fork point。
    pub fn fork_point(&self, left: Uint256, right: Uint256) -> Result<Uint256, ChainError> {
        let mut left = self
            .get(left)
            .ok_or(ChainError::UnknownBlock { hash: left })?;
        let mut right = self
            .get(right)
            .ok_or(ChainError::UnknownBlock { hash: right })?;

        while left.height > right.height {
            let prev = left
                .prev
                .ok_or(ChainError::UnknownBlock { hash: left.hash })?;
            left = self
                .get(prev)
                .ok_or(ChainError::UnknownBlock { hash: prev })?;
        }
        while right.height > left.height {
            let prev = right
                .prev
                .ok_or(ChainError::UnknownBlock { hash: right.hash })?;
            right = self
                .get(prev)
                .ok_or(ChainError::UnknownBlock { hash: prev })?;
        }
        while left.hash != right.hash {
            let left_prev = left
                .prev
                .ok_or(ChainError::UnknownBlock { hash: left.hash })?;
            let right_prev = right
                .prev
                .ok_or(ChainError::UnknownBlock { hash: right.hash })?;
            left = self
                .get(left_prev)
                .ok_or(ChainError::UnknownBlock { hash: left_prev })?;
            right = self
                .get(right_prev)
                .ok_or(ChainError::UnknownBlock { hash: right_prev })?;
        }

        Ok(left.hash)
    }
}
