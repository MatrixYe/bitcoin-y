# bitcoin-y

**用 Rust 从零实现比特币*

它展示还不是可运行的节点。这是一个刻意的学习产物：每个模块都对照 Bitcoin Core 的语义实现，
在 `docs/` 里有对应设计文档，并有集成测试覆盖，目的是让"理解"可以被**证明**，而不是只靠声称。

| | |
|---|---|
| 库代码 | **7,255** 行 Rust（`src/`） |
| 测试代码 | **2,245** 行 Rust（`tests/`） |
| 集成测试 | **125 个，全部通过**（19 个测试文件 + 1 个 doctest） |
| 设计文档 | **19 篇**（`docs/`） |
| Edition | Rust 2024 |

```bash
cargo test     # → 125 passed; 0 failed
```

---

## 它是什么，不是什么

**是什么：** 对比特币中"光看规格说明写不对"的那些部分，做了一次逐字节对齐的重实现——
序列化、compact/target 编码、`CScriptNum` 整数语义、难度重定目标算法、
区块索引/链工作量分叉选择的数据结构，以及脚本解释器的操作码分组。

**不是什么：** 不是节点。没有网络层、没有区块验证流水线、没有重组执行、也没有矿工。
各边界的准确位置见 [模块状态](#模块状态)——那张表就是"完成度如何"这个问题的诚实答案。

---

## 模块状态

| 模块            |    行数 | 状态     | 说明                                                                                                                                                                                                 |
| ------------- | ----: | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `uint256`     |   486 | ✅ 完成   | `GetCompact`/`SetCompact`、`bits`、`low64`、移位、回绕运算、比较；hash256 字节序转换                                                                                                                                  |
| `bignum`      |   562 | ✅ 基本完成 | 基于 `num_bigint` 的 `CScriptNum` 风格有符号大整数；`[u8]` ↔ `BigNum` 带符号处理、hex、运算符重载。`serialize`/`unserialize` 仍是 `unimplemented!()`                                                                          |
| `hash`        |    32 | ✅ 完成   | SHA-256、RIPEMD-160、HASH160、双 SHA-256                                                                                                                                                               |
| `codec`       |   336 | ✅ 完成   | `CompactSize` 变长整数、小端整数编解码                                                                                                                                                                         |
| `params`      |   329 | ✅ 完成   | 网络常量、创世块、`pow_target_limit`、目标间隔/周期                                                                                                                                                                |
| `block`       |   301 | ✅ 完成   | 区块头 + 区块体、区块哈希、序列化                                                                                                                                                                                 |
| `transaction` |   244 | ✅ 完成   | `TxIn`/`TxOut`/`OutPoint`、txid、序列化                                                                                                                                                                 |
| `merkle`      |   238 | ✅ 完成   | 根构建（9 个测试）。生成默克尔**证明路径**仍是 `todo!()`                                                                                                                                                               |
| `chain`       |   549 | ✅ 基本完成 | `BlockIndex` + `BlockTree`：`add_header`、`set_best_chain`、`active_chain`、`get_active_hash_at_height`、`fork_point`、`get_median_time_past`、链工作量 vs 无效工作量。`disconnect_path`/`connect_path` 是 `todo!()` |
| `utxo`        |   267 | ✅ 基本完成 | `UtxoSet` 的 `spend_output` / `connect_transaction`；`ConnectBlockUndo` 只有骨架                                                                                                                         |
| `mempool`     |   469 | ✅ 完成   | 手续费/大小/sig-op 统计、带 UTXO 校验的 `accept_to_mempool`、池内双花处理、在大小与 sig-op 限制下收集区块模板                                                                                                                       |
| `pow`         |   116 | ✅ 完成   | `GetNextWorkRequired`（2016 块重定目标，含 ¼–4× 时间跨度钳制与 pow 上限下限）和 `CheckProofOfWork`                                                                                                                      |
| `script/*`    | 2,421 | ✅ 基本完成 | parser、操作码表（117 个操作码）、builder、1,022 行的 interpreter、规则层、错误类型。**签名类操作码未实现**                                                                                                                          |
| `wallet/*`    |   389 | ✅ 基本完成 | secp256k1 密钥、DER + compact ECDSA 签名、`sign_digest`/`verify_digest`、由公钥生成 P2PKH 地址、Base58Check 编码与校验                                                                                                 |
| `store`       |   181 | 🚧 部分  | 定义了 `BlockStore` / `ChainStore` / `UtxoStore` / `WalletStore` 四个 trait；SQLite 后端建了表结构和 `DB::new`/`init`，但还没挂到 trait 后面                                                                             |
| `validation`  |    44 | ❌ 骨架   | `process_block`、`accept_block`、`connect_block`、`reorganize`——全部是 `todo!()`                                                                                                                         |
| `node`        |    34 | ❌ 骨架   | 只有 `NodeState { chain, mempool }` 结构体                                                                                                                                                              |
| `p2p`         |     7 | ❌ 骨架   | 仅在模块注释里写了设计意图                                                                                                                                                                                      |
| `bin/miner`   |    21 | ❌ 骨架   | 空的 `main`——参数解析、钱包初始化、调用 miner 服务都只写在注释里                                                                                                                                                           |

### 测试覆盖分布

| 测试文件 | 用例数 |
|---|---:|
| `bignum_test.rs` | 16 |
| `uint256_test.rs` | 14 |
| `script_parse_test.rs` | 12 |
| `merkle_test.rs` | 9 |
| `script_interpreter_bit_logic_test.rs` | 9 |
| `script_interpreter_numeric_test.rs` | 9 |
| `script_interpreter_stack_test.rs` | 8 |
| `hash_test.rs` | 7 |
| `opcode_test.rs` | 7 |
| `script_interpreter_control_expansion_test.rs` | 7 |
| `chain_test.rs` | 6 |
| `script_interpreter_splice_test.rs` | 6 |
| `codec_test.rs` | 5 |
| `compact_work_test.rs` | 5 |
| `script_builder_test.rs` | 5 |
| **合计** | **125** |

---

## 值得读的设计笔记

下面这些是"照着规格写"不够用、必须对齐 Bitcoin Core 实际行为的地方。
每一条在 `docs/` 里都有对应文档。

### 1. 字节序是数据模型决策，不是格式化细节

比特币混用字节序的方式，会产生静默且灾难性的 bug：

- 区块头字段在协议上是**小端**。
- 作为哈希显示出来的 `uint256` 值，相对其内部表示是**反的**
  （`Uint256::from_bytes` 在计算哈希时使用原始小端字节；`Display` 会反转）。
- `CompactSize` 变长长度是小端；compact target 的浮点表示则近似大端。

因此 `Uint256` 把"内部字"、"协议字节"和"哈希显示"三种转换分别暴露，
并用 `test_uint256_hash256_conversion_uses_raw_little_endian_bytes` 把最后一种钉住。
文档见 `docs/大端序小端序.md` 与 `docs/笔记-序列化.md`。

### 2. `nBits` / compact target 编码的双向转换

`SetCompact` 和 `GetCompact` 在相反方向上都**有损**，而 Bitcoin Core 对符号位
和尾数移位边界情况的规则并不在原始白皮书里。

- `test_uint256_compact` 和 `test_uint256_compact_sign_bit_adjusts_size` 覆盖了往返转换
  以及"符号位占用尾数一位"的情况。
- `compact_work_test.rs`（5 个测试）覆盖**工作量**一侧：
  `get_block_work` / `get_chain_work`，也就是驱动分叉选择的那两个函数。

### 3. 难度重定目标是"移植"，不是"转述"

`pow::get_next_work_required` 严格按 `GetNextWorkRequired` 的步骤实现：
创世块短路、非调整点直接沿用 `last.bits`、2016 块的时间跨度、
**钳制到 `[target_timespan/4, target_timespan*4]`**、
`new_target = old_target * actual / target`，以及 pow 上限下限。
这里的饱和运算是必要的：面对畸形链，重定目标计算不能 panic
（`docs/挖矿的核心流程.md`、`docs/挖矿全流程.md`）。

### 4. `CScriptNum` 不是"一个整数"

脚本数值是小端、符号-数值（sign-magnitude）表示、变长，并且有最大长度约束。
`BigNum` 是**为了复现这些语义**而建立在 `num_bigint::BigInt` 之上的，
不是要做通用大整数库——所以运算符重载必须手写
（`docs/算数运算符.md`、`docs/数值关系.md`）。

### 5. 脚本引擎按原版的接缝切分

脚本解释器不是一个大 switch，而是严格按操作码族分组，每组有独立测试文件：

| 分组 | 代表操作码 |
|---|---|
| 数据压栈 | 直接压栈 `0x01–0x4b`、`PUSHDATA1/2/4`、`OP_0`、`OP_1NEGATE`、`OP_1..OP_16` |
| 栈操作 | `DROP` `DUP` `SWAP` `OVER` `IFDUP` `NIP` `ROT` `TUCK` `2DROP` `2DUP` `3DUP` `2OVER` `2SWAP` `2ROT` `DEPTH` `PICK` `ROLL` `TOALTSTACK` `FROMALTSTACK` |
| 位逻辑 | `INVERT` `AND` `OR` `XOR` `EQUAL` `EQUALVERIFY` |
| 字符串切分 | `CAT` `SUBSTR` `LEFT` `RIGHT` `SIZE`（语义已实现；`CAT`/`SUBSTR`/`LEFT`/`RIGHT` 与原版一致置为禁用） |
| 数值运算 | `1ADD` `1SUB` `NEGATE` `ABS` `NOT` `0NOTEQUAL` `ADD` `SUB` `MUL` `DIV` `MOD` `LSHIFT` `RSHIFT` `BOOLAND` `BOOLOR` `NUMEQUAL(VERIFY)` `LESSTHAN` `GREATERTHAN` `MIN` `MAX` `WITHIN` |
| 流程控制 | `IF` `NOTIF` `ELSE` `ENDIF` `VERIFY` `RETURN` |
| 密码学 | `RIPEMD160` `SHA1` `SHA256` `HASH160` `HASH256` ✅ —— `CHECKSIG*` / `CHECKMULTISIG*` ❌ |

`count_sig_ops` 复现了 `CScript::GetSigOpCount`：包括跳过压栈数据的扫描逻辑，
以及对多签的保守 `+20`。被禁用的操作码被建模为规则层（`script/rules.rs`）而不是删掉，
这样失败模式与原版一致（`docs/脚本系统-指令集大纲.md`、`docs/笔记-脚本系统.md`）。

### 6. 内存池内的双花

同一笔输出的未确认花费不会被 UTXO 集拦住——因为输出还在 UTXO 集里。
内存池必须自己跟踪互相冲突的花费。`docs/池内双花情况.md` 把这个场景走了一遍，
而强制点在 `Mempool::accept_to_mempool`。

### 7. 分叉选择看的是链工作量，不是高度

`BlockTree` 把 `best_chain_work` 和 `best_invalid_work` 分开维护，
把 `active_chain` 作为哈希列表跟踪，并暴露 `get_active_hash_at_height`——
这正好是 `get_next_work_required` 往回找 2016 个区块所需要的能力。
`fork_point(left, right)` 已实现；但真正重组需要的
`disconnect_path`/`connect_path` 这一对还没有
（`docs/区块树结构设计.md`、`docs/解决分叉问题.md`）。

---

## 构建与测试

需要 Rust 1.85+（edition 2024）。

```bash
git clone https://github.com/MatrixYe/bitcoin-y && cd bitcoin-y

make test                 # cargo test —— 全部 125 个集成测试
make test-show-output     # 同上，但显示 println! 输出
make test-single-thread   # 单线程顺序执行，输出更好读
make test-specific FILE=merkle_test
make test-with-ignored    # 包含被 #[ignore] 标记的测试
make clean
```

```bash
cargo run                 # 打印主网创世块哈希
RUST_LOG=debug cargo run --bin miner   # bin/miner 是骨架——它只描述了自己打算做什么
```

## 设计文档（`docs/`）

| 主题 | 文档 |
|---|---|
| 整体架构 | `整体架构设计.md`、`全局状态.md`、`区块树结构设计.md`、`自定义编程规范.md` |
| 序列化与编码 | `笔记-序列化.md`、`交易序列化.md`、`大端序小端序.md` |
| 数值系统 | `算数运算符.md`、`数值关系.md` |
| 脚本引擎 | `笔记-脚本系统.md`、`脚本系统-指令集大纲.md`、`脚本系统-数据编码.md`、`脚本-原版速记.md` |
| 挖矿与共识 | `挖矿的核心流程.md`、`挖矿全流程.md`、`挖矿流程纲要.md` |
| 内存池与分叉处理 | `池内双花情况.md`、`解决分叉问题.md`、`挖矿和p2p接收新区块的交叉逻辑.md` |

---

## 技术栈

```
语言       Rust（edition 2024）
密码学     secp256k1 0.31（ECDSA、密钥生成、DER/compact）、sha2、sha1、ripemd、bs58、hex
大整数     num-bigint 0.4、num-traits 0.2
存储       rusqlite 0.39（bundled SQLite）
错误       thiserror 2.0
日志       log + env_logger
```

---

## 后续计划——要做到什么程度才算节点

按依赖顺序排列，因为每一层都依赖上一层：

1. **`script/verify.rs`** —— 接通 `CHECKSIG`/`CHECKMULTISIG`（需要交易/签名哈希上下文，
   而 `wallet/key.rs` 已经提供了），并补完 `validation.rs`。
2. **`validation`** —— `process_block` → `accept_block` → `connect_block`，
   然后用 `chain.rs` 里已经画好草图的 `disconnect_path`/`connect_path` 实现 `reorganize`。
3. **把存储挂到 trait 后面** —— 在现有 SQLite 表结构之上实现
   `BlockStore`/`ChainStore`/`UtxoStore`，让链上状态能跨重启保留。
4. **`node`** —— 把 `NodeState` 变成事件循环（`BlockReceived`、`TipChanged`）。
5. **`p2p`** —— 版本握手、`inv`/`getdata`/`block`/`tx` 消息编解码，以及区块下载调度器。
   挖矿与 p2p 的交互已经写在 `挖矿和p2p接收新区块的交叉逻辑.md` 里。
6. **`bin/miner`** —— 用 `Mempool::collect_for_block` 加 coinbase 组装区块，
   然后搜索 nonce 空间。
7. **先做 regtest。** `params.rs` 已经建模了 `Network`；一个 pow 上限很低的 regtest 模式
   能让整条流水线以毫秒级测试，而不是对着主网。

已知的小缺口：`BigNum::serialize`/`unserialize`、`merkle` 证明路径、`ConnectBlockUndo`，
以及 `store/` 里多余的 `user` 表和 `test()` 函数。

---

## 参考资料

- [Raw Transaction Format](https://bitcoindevelopers.org/docs/reference/transactions-ref/#raw-transaction-format)
- [CompactSize Unsigned Integers](https://bitcoindevelopers.org/docs/reference/transactions-ref/#compactsize-unsigned-integers)
- [Block Headers](https://developer.bitcoin.org/reference/block_chain.html#block-headers)
- [Serialized Blocks](https://developer.bitcoin.org/reference/block_chain.html#serialized-blocks)
- [Bitcoin Core `block.h`](https://doxygen.bitcoincore.org/block_8h_source.html)
- [Bitcoin Core `serialize.h`](https://doxygen.bitcoincore.org/serialize_8h_source.html)
