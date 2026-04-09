use log::{debug, error, info};
/// @Name: db
///
/// @Date: 2026/4/9 04:21
///
/// @Author: Matrix.Ye
///
use rusqlite::Connection;

// 1. 区块数据 - 区块头和区块体
// 2. UTXO集 - 未花费交易输出
// 3. 区块索引 - 区块哈希到区块位置的映射
// 4. 链状态 - 当前最佳链、高度等
// 5. 钱包数据 - 密钥、交易记录等
// 6. 交易索引 - txid 到区块位置的映射（可选）

macro_rules! open {
    ($db:expr) => {
        Connection::open($db)
    };
}
macro_rules! exe {
    ($db:expr, $sql:expr) => {
        $db.execute($sql, ())
    };
}
macro_rules! query {
    ($db:expr, $sql:expr) => {
        $db.query_row($sql, (), |r| r.get::<usize, String>(0))
    };
}

//-- 区块头
// CREATE TABLE blocks (
//     hash BLOB PRIMARY KEY,
//     height INTEGER UNIQUE,
//     version INTEGER,
//     prev_hash BLOB,
//     merkle_root BLOB,
//     timestamp INTEGER,
//     bits INTEGER,
//     nonce INTEGER,
//     raw_hex TEXT
// );
//-- 交易
//CREATE TABLE transactions (
//     txid BLOB PRIMARY KEY,
//     block_hash BLOB,
//     raw_hex TEXT,                     -- 可读：十六进制
//     FOREIGN KEY (block_hash) REFERENCES blocks(hash)
// );

//-- UTXO集
// CREATE TABLE utxos (
//     outpoint TEXT PRIMARY KEY,        -- txid:vout 格式，可读
//     value INTEGER,
//     script_pubkey TEXT,               -- 可读：十六进制
//     height INTEGER
// );

//-- 链状态
// CREATE TABLE chain_state (
//     key TEXT PRIMARY KEY,
//     value TEXT
// );

//-- 钱包
//CREATE TABLE keys (
//     address TEXT PRIMARY KEY,
//     secret_key TEXT,                  -- 加密存储
//     public_key TEXT,
//     label TEXT
// );

pub struct DB {
    conn: Connection,
}
impl DB {
    pub(crate) fn new(db: &str) -> Self {
        DB {
            conn: open!(db).unwrap(),
        }
    }
    //
    pub fn init(&self) {
        let mut sqls: Vec<&str> = vec![];
        sqls.push("CREATE TABLE IF NOT EXISTS user(id INTEGER PRIMARY KEY,name TEXT)");
        sqls.push("CREATE TABLE IF NOT EXISTS blocks (hash BLOB PRIMARY KEY,height INTEGER UNIQUE,version INTEGER,prev_hash BLOB,merkle_root BLOB,timestamp INTEGER,bits INTEGER,nonce INTEGER,raw_hex TEXT);" );
        sqls.push("CREATE TABLE IF NOT EXISTS transactions (txid BLOB PRIMARY KEY,block_hash BLOB,raw_hex TEXT,FOREIGN KEY (block_hash) REFERENCES blocks(hash));");
        sqls.push("CREATE TABLE IF NOT EXISTS utxos (outpoint TEXT PRIMARY KEY,value INTEGER,script_pubkey TEXT,height INTEGER);");
        sqls.push("CREATE TABLE IF NOT EXISTS chain_state (key TEXT PRIMARY KEY,value TEXT);");
        sqls.push("CREATE TABLE IF NOT EXISTS keys (address TEXT PRIMARY KEY,secret_key TEXT,public_key TEXT,label TEXT);");

        sqls.into_iter().for_each(|sql| {
            let result = exe!(self.conn, sql);
            // println!("{:?}", result);
            info!("SQL: {:?}", sql);
            info!("{:?}", result.err());
            debug!("this is debug");
            error!("this is error");
        });
        // let _ = sqls
        //     .iter()
        //     .map(|x| exe!(self.conn, x))
        //     .collect::<Vec<_>>()
        //     .iter()
        //     .map(|x| println!("x.is_err():{:?}", x.is_err()));
    }
    pub fn get_block(&self) {
        query!(self.conn, "SELECT * FROM block").unwrap();
    }
}
