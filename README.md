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

### 数值系统

比特币中的那些“数”

#### BigNum

继承自num_bigint::BigInt,实现其rust风味的语义。BigNum表示大数，无精度，有符号，可运算，大部分用于比特币脚本中的数值计算。与uint256需要区分开来，后者有精度，无符号，主要用于哈希、工作量、未压缩难度。

-[x] 纯数值 usize,i8,i16,164,u32,u64与BigNum的相互转化，`from_*`和`to_*`
-[x] 字节流`[u8]`与`BigNum`的相互转化，非常重要，需要考虑小端序和原版中的正负号处理
-[ ] `uint256` 与`BigNum`的转化
-[x] `hex` 与`BigNum`的转化
-[ ] 序列化与反序列化
-[x] 正负号、零、符号的处理函数
-[x] 运算符重载：算数运算符必须手动重写
-[x] 运算符重载：比较运算符可以通过`特征属性`，交给编译器自动实现，无所谓
-[x] 一些其他特征，Default，Display配合调试使用

#### uint256
todo
### 脚本系统

#### 架构设计

实现一个图灵机范式的比特币脚本引擎

-[x] 按照图灵范式，将数据与指令分离
-[x] 操作码分组，区分数据压栈与其他操作
-[x] 栈机操作流，操作码、执行层、验证层、规则层
-[x] 禁用操作码抽象成为Rule层

#### 功能

-[x] 数值操作Direct Data Push: 0x01~0x4b 特殊字节范围
-[x] 数值操作`PushOP` 组：OpPushData1/2/4
-[x] 数值操作`PushOP` 组：OP0,OP_neg,Op1~OP16
-[x] 数值操作`PushOP` 组： OpReserved
-[x] 栈机操作`StackOp`组:Drop、Dup、Swap、Over、IfDu
-[x] 栈机操作`StackOp`组:Drop、Dup、Swap、Over、IfDup
-[x] 栈机操作`StackOp`组:ToAltStack、FromAltStack
-[x] 栈机操作`StackOp`组:Op2Drop、Op2Dup、Op3Dup
-[x] 栈机操作`StackOp`组:Nip、Rot、Tuck
-[x] 栈机操作`StackOp`组:Op2Over、Op2Swap、Op2Rot
-[x] 栈机操作`StackOp`组:Depth、Pick、Roll


-[x] 逻辑运算`BitLogicOp`组:OpInvert、OpAnd、OpOr、OpXor,浴火绯异或(语义实现，代码禁用）
-[x] 逻辑运算`BitLogicOp`组:OpEqual：逻辑等。弹出栈顶两个元素，比较字节相等，相等压入true，反之压入false
-[x] 逻辑运算`BitLogicOp`组:OpEqualVerify：逻辑等验。先执行OpEqual 再执行 OpVerify


-[x] 字符操作`SpliceOp` 组:OpCat 拼接 （语义实现，代码禁用）
-[x] 字符操作`SpliceOp` 组:OpSubStr 截取 （语义实现，代码禁用）
-[x] 字符操作`SpliceOp` 组:OpLeft 左截取 （语义实现，代码禁用）
-[x] 字符操作`SpliceOp` 组:OpRight 右截取（语义实现，代码禁用）
-[x] 字符操作`SpliceOp` 组:OpSize 栈顶元素长度压栈


-[ ] `NumericOp` 组，有点难，先实现一个 script_num 辅助模块
-[ ] `NumericOp` 组:OP_1ADD / OP_1SUB：栈顶数字加 1 / 减 1
-[ ] `NumericOp` 组:OP_2MUL / OP_2DIV 栈顶数字乘 2 / 除 2，原版用位移实现；（语义实现，代码禁用）
-[ ] `NumericOp` 组:OP_NEGATE / OP_ABS：取负 / 取绝对值
-[ ] `NumericOp` OP_1ADD / OP_1SUB：栈顶数字加 1 / 减 1
-[ ] `NumericOp` OP_2MUL / OP_2DIV 栈顶数字乘 2 / 除 2，原版用位移实现；（语义实现，代码禁用）
-[ ] `NumericOp` OP_NEGATE / OP_ABS：取负 / 取绝对值
-[ ] `NumericOp` OP_NOT 数字等于 0 输出 true，否则 false
-[ ] `NumericOp` OP_0NOTEQUAL：数字不等于 0 输出 true，否则 false
-[ ] `NumericOp` OP_ADD / OP_SUB / OP_MUL / OP_DIV / OP_MOD：二元算术，按 `[left, right] -> left op right`。
-[ ] `NumericOp` OP_LSHIFT / OP_RSHIFT：按 right 位移 left，原版限制 shift 在 0..=2048。
-[ ] `NumericOp` OP_BOOLAND / OP_BOOLOR：把两个数字按“是否非零”解释成布尔值。
-[ ] `NumericOp` OP_NUMEQUAL / OP_NUMNOTEQUAL：数值相等/不相等，不是字节相等
-[ ] `NumericOp` OP_NUMEQUALVERIFY：数值相等则消耗两个元素且不压栈，不相等返回 VerifyFailed
-[ ] `NumericOp` OP_LESSTHAN / OP_GREATERTHAN / OP_LESSTHANOREQUAL / OP_GREATERTHANOREQUAL：数值比较。
-[ ] `NumericOp` OP_MIN / OP_MAX：取较小/较大值。
-[ ] `NumericOp` OP_WITHIN：判断 min <= value < max。

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
