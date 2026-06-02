use crate::codec::serialize_block_header;
use crate::hash::sha256d;
use crate::transaction::Transaction;
use crate::uint256::Uint256;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BlockHeader {
    pub version: i32,
    pub prev_block: Uint256,
    pub merkle_root: Uint256,
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Block {
    pub header: BlockHeader,
    pub txdata: Vec<Transaction>,
}

impl BlockHeader {
    /// 计算传统 Bitcoin 区块头哈希。
    pub fn block_hash(&self) -> Uint256 {
        let head_ser = self.serialize();
        sha256d(&head_ser).into()
    }

    /// 区块头序列化
    pub fn serialize(&self) -> Vec<u8> {
        serialize_block_header(self).to_vec()
    }
}

impl Block {
    /// 获取区块哈希，即区块头哈希
    pub fn get_hash(&self) -> Uint256 {
        self.header.block_hash()
    }

    // 根据交易 txid 计算默克尔根。
    // pub fn merkle_root(&self) -> Uint256 {
    //     todo:fix it 
    // let layer = self.txdata.iter().map(|tx| tx.txid().0).collect::<Vec<_>>();
    // make_merkle_root(Uint256::from_words(layer)).into()
    // }
}
