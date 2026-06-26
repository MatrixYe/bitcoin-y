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
/// 再由 `BlockTree` 统一持有 `HashMap<Uint256, BlockIndex>`，避免自引用结构和生命周期复杂度。
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

// 计算当前区块的工作量
fn get_work_from_nbits(nbits: u32) -> BigNum {
    let a = BigNum::from_u32(1) << 256;
    let target = BigNum::set_compact(nbits);
    if target <= BigNum::ZERO {
        BigNum::ZERO
    } else {
        a / (target + BigNum::from_u32(1))
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

#[derive(Debug, Clone, Default)]
pub struct BlockTree {
    /// 原版 `mapBlockIndex`：所有已知区块索引，key 是区块哈希。
    indexes: HashMap<Uint256, BlockIndex>,
    /// 所有子分支。原版没有单独保存这个表，主要靠 `pprev` 反查；Rust 中显式保存更方便。
    children: HashMap<Uint256, Vec<Uint256>>,
    /// 原版 `pindexGenesisBlock` 的 hash 版本。
    genesis: Option<Uint256>,
    /// 原版 `hashBestChain` / `pindexBest` 的 hash 版本。
    best: Option<Uint256>,
    /// 原版 `nBestHeight`。
    best_height: Option<u32>,
    /// 原版 `bnBestChainWork`。
    best_chain_work: BigNum,
    /// 原版 `bnBestInvalidWork`，当前先保存状态，后续接入无效链处理。
    best_invalid_work: BigNum,
    /// 当前最佳链，`active_chain[height] = hash`。这是 `pnext` 的 Rust 化辅助索引。
    active_chain: Vec<Uint256>,
}

impl BlockTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// 从存储记录恢复内存区块树。具体存储模块后续实现时可以直接调用这里。
    pub fn from_indexes(
        indexes: Vec<BlockIndex>,
        best: Option<Uint256>,
    ) -> Result<Self, ChainError> {
        let mut tree = Self::new();

        for index in indexes {
            let hash = index.hash();
            if tree.indexes.contains_key(&hash) {
                return Err(ChainError::DuplicateBlock { hash });
            }
            if index.is_genesis() {
                tree.genesis = Some(hash);
            }
            if let Some(prev) = index.prev {
                tree.children.entry(prev).or_default().push(hash);
            }
            tree.indexes.insert(hash, index);
        }

        let best = match best {
            Some(best) => Some(best),
            None => tree
                .indexes
                .values()
                .max_by(|left, right| left.chain_work.cmp(&right.chain_work))
                .map(BlockIndex::hash),
        };
        if let Some(best) = best {
            tree.set_best_chain(best)?;
        }
        Ok(tree)
    }

    pub fn len(&self) -> usize {
        self.indexes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.indexes.is_empty()
    }

    pub fn contains(&self, hash: Uint256) -> bool {
        self.indexes.contains_key(&hash)
    }

    pub fn get(&self, hash: Uint256) -> Option<&BlockIndex> {
        self.indexes.get(&hash)
    }

    pub fn genesis_hash(&self) -> Option<Uint256> {
        self.genesis
    }

    pub fn best_hash(&self) -> Option<Uint256> {
        self.best
    }

    pub fn best_index(&self) -> Option<&BlockIndex> {
        self.best.and_then(|hash| self.get(hash))
    }

    pub fn best_height(&self) -> Option<u32> {
        self.best_height
    }

    pub fn best_chain_work(&self) -> &BigNum {
        &self.best_chain_work
    }

    pub fn best_invalid_work(&self) -> &BigNum {
        &self.best_invalid_work
    }

    pub fn active_chain(&self) -> &[Uint256] {
        &self.active_chain
    }

    pub fn active_hash_at_height(&self, height: u32) -> Option<Uint256> {
        self.active_chain.get(height as usize).copied()
    }

    pub fn children(&self, hash: Uint256) -> &[Uint256] {
        self.children.get(&hash).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn add_genesis(&mut self, header: &BlockHeader) -> Result<Uint256, ChainError> {
        if let Some(hash) = self.genesis {
            return Err(ChainError::GenesisAlreadyExists { hash });
        }
        let hash = self.insert_index(header, None)?;
        self.genesis = Some(hash);
        self.set_best_chain(hash)?;
        Ok(hash)
    }

    pub fn add_header(&mut self, header: &BlockHeader) -> Result<Uint256, ChainError> {
        let prev_hash = header.prev_block;
        let prev = self
            .indexes
            .get(&prev_hash)
            .ok_or(ChainError::UnknownPrevBlock { prev: prev_hash })?
            .clone();
        let hash = self.insert_index(header, Some(&prev))?;

        let should_update_best = match self.best_index() {
            Some(best) => self.indexes[&hash].chain_work > best.chain_work,
            None => true,
        };
        if should_update_best {
            self.set_best_chain(hash)?;
        }

        Ok(hash)
    }

    fn insert_index(
        &mut self,
        header: &BlockHeader,
        prev: Option<&BlockIndex>,
    ) -> Result<Uint256, ChainError> {
        let hash = header.hash();
        if self.indexes.contains_key(&hash) {
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
    pub fn set_best_chain(&mut self, tip: Uint256) -> Result<(), ChainError> {
        if !self.indexes.contains_key(&tip) {
            return Err(ChainError::UnknownBlock { hash: tip });
        }

        for index in self.indexes.values_mut() {
            index.next = None;
        }

        let mut path = Vec::new();
        let mut current = Some(tip);
        while let Some(hash) = current {
            let index = self
                .indexes
                .get(&hash)
                .ok_or(ChainError::UnknownBlock { hash })?;
            path.push(hash);
            current = index.prev;
        }
        path.reverse();

        for window in path.windows(2) {
            let prev = window[0];
            let next = window[1];
            self.indexes
                .get_mut(&prev)
                .ok_or(ChainError::UnknownBlock { hash: prev })?
                .next = Some(next);
        }

        let best = self
            .indexes
            .get(&tip)
            .ok_or(ChainError::UnknownBlock { hash: tip })?;
        self.best = Some(tip);
        self.best_height = Some(best.height);
        self.best_chain_work = best.chain_work.clone();
        self.active_chain = path;
        Ok(())
    }

    pub fn is_in_best_chain(&self, hash: Uint256) -> bool {
        let Some(index) = self.get(hash) else {
            return false;
        };
        self.active_hash_at_height(index.height) == Some(hash)
    }

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
