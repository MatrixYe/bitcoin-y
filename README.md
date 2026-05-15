# Bitcoin-Y

一个用于研究比特币底层原理与基础实现的 Rust 项目。

## 项目说明

当前代码主要围绕以下方向展开：

- 交易与区块的数据结构
- Bitcoin 传统序列化与反序列化
- 哈希计算与默克尔根构建
- `nBits` 与目标值转换、PoW 基础校验
- 密钥、签名与地址生成
- 脚本系统的初步模块拆分

## 开发进度

### 脚本系统

-[x] 操作码分组
-[ ] 设计脚本系统流程解析、栈机、验证

#### 操作码代码逻辑实现

-[x] Direct Data Push
    -[x] 0x01~0x4b
-[x] PushOP 组
    -[x] OpPushData1/2/4
    -[x] OP0,OP_neg,Op1~OP16
    -[x] OpReserved
-[x] 数据 OP0,OP_neg,Op1~Op16
-[x] `StackOp`组，熟悉栈机运行原理
    -[x] Drop、Dup、Swap、Over、IfDup
    -[x] ToAltStack、FromAltStack
    -[x] Op2Drop、Op2Dup、Op3Dup
    -[x] Nip、Rot、Tuck
    -[x] Op2Over、Op2Swap、Op2Rot
    -[x] Depth、Pick、Roll
-[x] `BitLogicOp` 组
    - [x] OpInvert：逻辑取反 （语义实现，代码禁用）
    - [x] OpAnd：逻辑与（语义实现，代码禁用）
    - [x] OpOr：逻辑或（语义实现，代码禁用）
    - [x] OpXor：逻辑异或（语义实现，代码禁用）
    - [x] OpEqual：逻辑等。弹出栈顶两个元素，比较字节相等，相等压入true，反之压入false
    - [x] OpEqualVerify：逻辑等验。先执行OpEqual 再执行 OpVerify
-[x] `SpliceOp` 组
    -[x] OpCat 拼接 （语义实现，代码禁用）
    -[x] OpSubStr 截取 （语义实现，代码禁用）
    -[x] OpLeft 左截取 （语义实现，代码禁用）
    -[x] OpRight 右截取（语义实现，代码禁用）
    -[x] OpSize 栈顶元素长度压栈
-[ ] `NumericOp` 组，有点难，先实现一个 script_num 辅助模块
-[ ] `ControlOp` 组，暂缓，很难

## 参考资料

### 交易格式

- [Raw Transaction Format](https://bitcoindevelopers.org/docs/reference/transactions-ref/#raw-transaction-format)
- [CompactSize Unsigned Integers](https://bitcoindevelopers.org/docs/reference/transactions-ref/#compactsize-unsigned-integers)

### 区块与序列化

- [Block Headers](https://developer.bitcoin.org/reference/block_chain.html#block-headers)
- [Serialized Blocks](https://developer.bitcoin.org/reference/block_chain.html#serialized-blocks)
- [Block Chain Reference](https://bitcoindevelopers.org/docs/reference/block-chain-ref/)
- [Bitcoin Core `block.h`](https://doxygen.bitcoincore.org/block_8h_source.html)
- [Bitcoin Core `serialize.h`](https://doxygen.bitcoincore.org/serialize_8h_source.html)

### 默克尔树

- [Merkle Root Reference](https://bitcoindevelopers.org/docs/reference/block-chain-ref/)
