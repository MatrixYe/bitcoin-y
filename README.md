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
