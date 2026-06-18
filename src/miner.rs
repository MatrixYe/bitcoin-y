/// @Name: miner
///
/// @Date: 2026/6/2 16:33
///
/// @Author: Matrix.Ye
///
/// @Description:
/// ```text
/// GenerateBitcoins()
///   -> ThreadBitcoinMiner()
///   -> BitcoinMiner()
///   -> CreateNewBlock()
///   -> IncrementExtraNonce()
///   -> FormatHashBuffers()
///   -> ScanHash_CryptoPP() / ScanHash_4WaySSE2()
///   -> CheckWork()
///   -> ProcessBlock()
///   -> AcceptBlock()
///   -> AddToBlockIndex()
///   -> SetBestChain()
/// ```
use crate::block::{Block, BlockHeader};
use crate::chain::BlockIndex;
use crate::transaction::{OutPoint, Transaction, TxIn, TxOut};
use crate::uint256::Uint256;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MiningError {
    #[error("unknown block index")]
    UnknownBlockIndex,
}

pub fn bitcoin_miner(f_generate_bitcoins: bool) -> Result<(), MiningError> {
    // todo 1、准备挖矿的钱包 和 默认拓展搜索空间 nExtraNonce

    while f_generate_bitcoins {
        //todo 2、等待节点连接完成，等待区块同步完成

        // 创建待选区块
        let block = create_new_block()?;

        // 拓展搜索空间
    }
    Ok(())
}

/// 获取当前最佳链的位置，区块组成的是树结构
fn get_best_index() -> Result<BlockIndex, MiningError> {
    unimplemented!();
}

// 拓展搜索空间
fn increment_extra_nonce() {
    unimplemented!();
}

fn create_new_block() -> Result<Block, MiningError> {
    // 获取当前最佳位置
    let best_index = get_best_index()?;

    // 初始区块，提供前驱
    let mut block = Block {
        header: BlockHeader {
            version: 1,
            prev_block: best_index.hash(),
            merkle_root: Uint256::ZERO, //等价于Uint256::default()但语义更清晰
            time: 0,
            bits: 0,
            nonce: 0,
        },
        txdata: vec![],
    };

    // 创建coinbase交易
    let coinbase = create_coinbase();

    Ok(block)
}
fn create_coinbase() -> Transaction {
    //   // 创建coinbase交易
    //     //coinbase 的输入 `prevout` 是 null，输出脚本是“公钥 + OP_CHECKSIG”。这是早期风格，直接付给一个公钥，不是现代常见地址脚本模板的抽象表达
    //     // Create coinbase tx
    //     CTransaction txNew;
    //     txNew.vin.resize(1);
    //     txNew.vin[0].prevout.SetNull();
    //     txNew.vout.resize(1);
    //     txNew.vout[0].scriptPubKey << reservekey.GetReservedKey() << OP_CHECKSIG;
    let mut coinbase = Transaction::default();

    coinbase.vin = vec![TxIn {
        prevout: OutPoint::set_null(),
        script_sig: vec![], //todo
        sequence: u32::MAX,
    }];

    coinbase.vout = vec![TxOut {
        value: 0,              //todo 需要计算奖励+手续费
        script_pubkey: vec![], // todo 默认公钥
    }];

    coinbase
}
