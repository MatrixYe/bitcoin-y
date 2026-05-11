//! 脚本系统 操作码
///
/// @Date: 2026/4/24 02:55
///
/// @Author: Matrix.Ye
///
/// @Description: 操作码
///
/// 参考[bitcoin-v0.3.19/script.h](../../bitcoin-v0.3.19/script.h)
/// 和 Bitcoin Core 最新版本的 `src/script/script.h`。
///
/// 1. 操作码按 Bitcoin Core 注释分组。
/// 2. 每个具名操作码显式保存协议字节和原版 C++ 名称。
/// 3. 多个名称对应同一字节时，用关联常量别名表达。
///
/// 关于分组的解释：Bitcoin Script 的共识要求是：脚本按字节流解释，每条指令从一个字节开始。
/// 这个字节对应某种 opcode 或 push-data 前缀。
/// 至于源码里把这些 opcode 放在一个大 enum，还是拆成多个分组 enum，是实现层面的选择。
/// 我的目标是从语义级别去实现比特币，而非从语法级别实现比特币，因此代码实现上不只是机械翻译 C++，而是在原版语义的基础上加上自己的理解。
/// C++ 里 flat enum 加注释已经够用，因为它的解释器主要靠 switch(opcode)。
/// 但 Rust强大的enum 可以表达结构，把注释里的分类变成类型，可以让后续代码更清楚
/// 而且分组能减少解释器里的辅助判断，一些辅助方法`is_push`,`is_control`就不用再写了。
use std::fmt;







/// ## 操作码表,取自比特币维基百科
///
/// ### PushValue
///
/// | 操作码 | 字节码 | 原版名称 | 功能 |
/// | --- | --- | --- | --- |
/// | `Op0` | `0x00` | `OP_0` | 压入空字节串，数值语义为 0 |
/// | `OpFalse` | `Op0` | `OP_FALSE` | `Op0` 的别名，布尔语义为 false |
/// | `PushData1` | `0x4c` | `OP_PUSHDATA1` | 后续 1 字节表示待压栈数据长度 |
/// | `PushData2` | `0x4d` | `OP_PUSHDATA2` | 后续 2 字节表示待压栈数据长度 |
/// | `PushData4` | `0x4e` | `OP_PUSHDATA4` | 后续 4 字节表示待压栈数据长度 |
/// | `Op1Negate` | `0x4f` | `OP_1NEGATE` | 压入数值 -1 |
/// | `OpReserved` | `0x50` | `OP_RESERVED` | 保留操作码，执行时无效 |
/// | `Op1` | `0x51` | `OP_1` | 压入数值 1 |
/// | `OpTrue` | `Op1` | `OP_TRUE` | `Op1` 的别名，布尔语义为 true |
/// | `Op2` | `0x52` | `OP_2` | 压入数值 2 |
/// | `Op3` | `0x53` | `OP_3` | 压入数值 3 |
/// | `Op4` | `0x54` | `OP_4` | 压入数值 4 |
/// | `Op5` | `0x55` | `OP_5` | 压入数值 5 |
/// | `Op6` | `0x56` | `OP_6` | 压入数值 6 |
/// | `Op7` | `0x57` | `OP_7` | 压入数值 7 |
/// | `Op8` | `0x58` | `OP_8` | 压入数值 8 |
/// | `Op9` | `0x59` | `OP_9` | 压入数值 9 |
/// | `Op10` | `0x5a` | `OP_10` | 压入数值 10 |
/// | `Op11` | `0x5b` | `OP_11` | 压入数值 11 |
/// | `Op12` | `0x5c` | `OP_12` | 压入数值 12 |
/// | `Op13` | `0x5d` | `OP_13` | 压入数值 13 |
/// | `Op14` | `0x5e` | `OP_14` | 压入数值 14 |
/// | `Op15` | `0x5f` | `OP_15` | 压入数值 15 |
/// | `Op16` | `0x60` | `OP_16` | 压入数值 16 |
///
/// ---
///
/// ### Control
///
/// | 操作码 | 字节码 | 原版名称 | 功能 |
/// | --- | --- | --- | --- |
/// | `Nop` | `0x61` | `OP_NOP` | 空操作 |
/// | `Ver` | `0x62` | `OP_VER` | 版本相关保留操作码 |
/// | `If` | `0x63` | `OP_IF` | 条件分支开始 |
/// | `NotIf` | `0x64` | `OP_NOTIF` | 取反条件分支开始 |
/// | `VerIf` | `0x65` | `OP_VERIF` | 版本相关保留条件操作码 |
/// | `VerNotIf` | `0x66` | `OP_VERNOTIF` | 版本相关保留取反条件操作码 |
/// | `Else` | `0x67` | `OP_ELSE` | 条件分支的 else 分支 |
/// | `EndIf` | `0x68` | `OP_ENDIF` | 条件分支结束 |
/// | `Verify` | `0x69` | `OP_VERIFY` | 验证栈顶为真，否则失败 |
/// | `Return` | `0x6a` | `OP_RETURN` | 立即使脚本失败，常用于不可花费输出 |
///
/// ---
///
/// ### Stack
///
/// | 操作码 | 字节码 | 原版名称 | 功能 |
/// | --- | --- | --- | --- |
/// | `OpToAltStack` | `0x6b` | `OP_TOALTSTACK` | 将主栈栈顶移动到备用栈 |
/// | `FromAltStack` | `0x6c` | `OP_FROMALTSTACK` | 将备用栈栈顶移动到主栈 |
/// | `Op2Drop` | `0x6d` | `OP_2DROP` | 丢弃主栈顶两个元素 |
/// | `Op2Dup` | `0x6e` | `OP_2DUP` | 复制主栈顶两个元素 |
/// | `Op3Dup` | `0x6f` | `OP_3DUP` | 复制主栈顶三个元素 |
/// | `Op2Over` | `0x70` | `OP_2OVER` | 复制主栈中指定的两个较深元素到栈顶 |
/// | `Op2Rot` | `0x71` | `OP_2ROT` | 旋转主栈中的三组双元素 |
/// | `Op2Swap` | `0x72` | `OP_2SWAP` | 交换主栈顶两组双元素 |
/// | `IfDup` | `0x73` | `OP_IFDUP` | 栈顶为真时复制栈顶 |
/// | `Depth` | `0x74` | `OP_DEPTH` | 将当前主栈深度压栈 |
/// | `Drop` | `0x75` | `OP_DROP` | 丢弃主栈栈顶 |
/// | `Dup` | `0x76` | `OP_DUP` | 复制主栈栈顶 |
/// | `Nip` | `0x77` | `OP_NIP` | 删除栈顶下方的一个元素 |
/// | `Over` | `0x78` | `OP_OVER` | 复制栈顶下方的一个元素到栈顶 |
/// | `Pick` | `0x79` | `OP_PICK` | 复制指定深度的元素到栈顶 |
/// | `Roll` | `0x7a` | `OP_ROLL` | 移动指定深度的元素到栈顶 |
/// | `Rot` | `0x7b` | `OP_ROT` | 旋转主栈顶三个元素 |
/// | `Swap` | `0x7c` | `OP_SWAP` | 交换主栈顶两个元素 |
/// | `Tuck` | `0x7d` | `OP_TUCK` | 将栈顶复制到第二个元素下方 |
///
/// ---
///
/// ### Splice
///
/// | 操作码 | 字节码 | 原版名称 | 功能 |
/// | --- | --- | --- | --- |
/// | `Cat` | `0x7e` | `OP_CAT` | 拼接字节串，当前为禁用操作码 |
/// | `SubStr` | `0x7f` | `OP_SUBSTR` | 截取字节串，当前为禁用操作码 |
/// | `Left` | `0x80` | `OP_LEFT` | 取字节串左侧部分，当前为禁用操作码 |
/// | `Right` | `0x81` | `OP_RIGHT` | 取字节串右侧部分，当前为禁用操作码 |
/// | `Size` | `0x82` | `OP_SIZE` | 将栈顶元素的字节长度压栈 |
///
/// ---
///
/// ### BitLogic
///
/// | 操作码 | 字节码 | 原版名称 | 功能 |
/// | --- | --- | --- | --- |
/// | `Invert` | `0x83` | `OP_INVERT` | 按位取反，当前为禁用操作码 |
/// | `And` | `0x84` | `OP_AND` | 按位与，当前为禁用操作码 |
/// | `Or` | `0x85` | `OP_OR` | 按位或，当前为禁用操作码 |
/// | `Xor` | `0x86` | `OP_XOR` | 按位异或，当前为禁用操作码 |
/// | `Equal` | `0x87` | `OP_EQUAL` | 比较两个元素是否相等并压入结果 |
/// | `EqualVerify` | `0x88` | `OP_EQUALVERIFY` | 比较相等后执行验证 |
/// | `Reserved1` | `0x89` | `OP_RESERVED1` | 保留操作码 |
/// | `Reserved2` | `0x8a` | `OP_RESERVED2` | 保留操作码 |
///
/// ---
///
/// ### Numeric
///
/// | 操作码 | 字节码 | 原版名称 | 功能 |
/// | --- | --- | --- | --- |
/// | `Op1Add` | `0x8b` | `OP_1ADD` | 数值加 1 |
/// | `Op1Sub` | `0x8c` | `OP_1SUB` | 数值减 1 |
/// | `Op2Mul` | `0x8d` | `OP_2MUL` | 数值乘 2，当前为禁用操作码 |
/// | `Op2Div` | `0x8e` | `OP_2DIV` | 数值除 2，当前为禁用操作码 |
/// | `Negate` | `0x8f` | `OP_NEGATE` | 数值取负 |
/// | `Abs` | `0x90` | `OP_ABS` | 数值取绝对值 |
/// | `Not` | `0x91` | `OP_NOT` | 数值逻辑非 |
/// | `Op0NotEqual` | `0x92` | `OP_0NOTEQUAL` | 判断数值是否非 0 |
/// | `Add` | `0x93` | `OP_ADD` | 数值加法 |
/// | `Sub` | `0x94` | `OP_SUB` | 数值减法 |
/// | `Mul` | `0x95` | `OP_MUL` | 数值乘法，当前为禁用操作码 |
/// | `Div` | `0x96` | `OP_DIV` | 数值除法，当前为禁用操作码 |
/// | `Mod` | `0x97` | `OP_MOD` | 数值取模，当前为禁用操作码 |
/// | `LShift` | `0x98` | `OP_LSHIFT` | 左移，当前为禁用操作码 |
/// | `RShift` | `0x99` | `OP_RSHIFT` | 右移，当前为禁用操作码 |
/// | `BoolAnd` | `0x9a` | `OP_BOOLAND` | 布尔与 |
/// | `BoolOr` | `0x9b` | `OP_BOOLOR` | 布尔或 |
/// | `NumEqual` | `0x9c` | `OP_NUMEQUAL` | 数值相等比较 |
/// | `NumEqualVerify` | `0x9d` | `OP_NUMEQUALVERIFY` | 数值相等比较后执行验证 |
/// | `NumNotEqual` | `0x9e` | `OP_NUMNOTEQUAL` | 数值不等比较 |
/// | `LessThan` | `0x9f` | `OP_LESSTHAN` | 数值小于比较 |
/// | `GreaterThan` | `0xa0` | `OP_GREATERTHAN` | 数值大于比较 |
/// | `LessThanOrEqual` | `0xa1` | `OP_LESSTHANOREQUAL` | 数值小于等于比较 |
/// | `GreaterThanOrEqual` | `0xa2` | `OP_GREATERTHANOREQUAL` | 数值大于等于比较 |
/// | `Min` | `0xa3` | `OP_MIN` | 取两个数值中的较小值 |
/// | `Max` | `0xa4` | `OP_MAX` | 取两个数值中的较大值 |
/// | `Within` | `0xa5` | `OP_WITHIN` | 判断数值是否在指定区间内 |
///
/// ---
///
/// ### Crypto
///
/// | 操作码 | 字节码 | 原版名称 | 功能 |
/// | --- | --- | --- | --- |
/// | `Ripemd160` | `0xa6` | `OP_RIPEMD160` | 对栈顶元素计算 RIPEMD160 |
/// | `Sha1` | `0xa7` | `OP_SHA1` | 对栈顶元素计算 SHA1 |
/// | `Sha256` | `0xa8` | `OP_SHA256` | 对栈顶元素计算 SHA256 |
/// | `Hash160` | `0xa9` | `OP_HASH160` | 对栈顶元素计算 HASH160 |
/// | `Hash256` | `0xaa` | `OP_HASH256` | 对栈顶元素计算双 SHA256 |
/// | `CodeSeparator` | `0xab` | `OP_CODESEPARATOR` | 标记签名哈希使用的脚本分隔位置 |
/// | `CheckSig` | `0xac` | `OP_CHECKSIG` | 验证单个签名 |
/// | `CheckSigVerify` | `0xad` | `OP_CHECKSIGVERIFY` | 验证单个签名后执行验证 |
/// | `CheckMultiSig` | `0xae` | `OP_CHECKMULTISIG` | 验证多重签名 |
/// | `CheckMultiSigVerify` | `0xaf` | `OP_CHECKMULTISIGVERIFY` | 验证多重签名后执行验证 |
///
/// ---
///
/// ### Expansion
///
/// | 操作码 | 字节码 | 原版名称 | 功能 |
/// | --- | --- | --- | --- |
/// | `Nop1` | `0xb0` | `OP_NOP1` | 预留扩展空操作码 |
/// | `Nop2` | `0xb1` | `OP_NOP2` | 预留扩展空操作码，后续重定义为 CLTV |
/// | `CheckLockTimeVerify` | `Nop2` | `OP_CHECKLOCKTIMEVERIFY` | `Nop2` 的软分叉语义别名，检查绝对锁定时间 |
/// | `Nop3` | `0xb2` | `OP_NOP3` | 预留扩展空操作码，后续重定义为 CSV |
/// | `CheckSequenceVerify` | `Nop3` | `OP_CHECKSEQUENCEVERIFY` | `Nop3` 的软分叉语义别名，检查相对锁定时间 |
/// | `Nop4` | `0xb3` | `OP_NOP4` | 预留扩展空操作码 |
/// | `Nop5` | `0xb4` | `OP_NOP5` | 预留扩展空操作码 |
/// | `Nop6` | `0xb5` | `OP_NOP6` | 预留扩展空操作码 |
/// | `Nop7` | `0xb6` | `OP_NOP7` | 预留扩展空操作码 |
/// | `Nop8` | `0xb7` | `OP_NOP8` | 预留扩展空操作码 |
/// | `Nop9` | `0xb8` | `OP_NOP9` | 预留扩展空操作码 |
/// | `Nop10` | `0xb9` | `OP_NOP10` | 预留扩展空操作码 |
/// | `CheckSigAdd` | `0xba` | `OP_CHECKSIGADD` | Tapscript 中累加通过验证的签名数量 |
///
/// ---
///
/// ### Invalid
///
/// | 操作码 | 字节码 | 原版名称 | 功能 |
/// | --- | --- | --- | --- |
/// | `InvalidOpcode` | `0xff` | `OP_INVALIDOPCODE` | 无效操作码 |
macro_rules! opcode_group {
    ($vis:vis enum $name:ident {
        $($variant:ident => ($byte:literal, $text:literal)),* $(,)?
    }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        $vis enum $name {
            $($variant),*
        }

        /*byte()表达的是值语义的转化，而不是借用对象状态，因此用self而不是&self符合其他标准库的写法
        因为OpCode派生了Copy特征，所以不会造成所有权移动的问题
        假如以后枚举中携带了String、Vec这种堆上数据，那么需要考虑使用&self
        */

        impl $name {
            pub const fn byte(self) -> u8 {
                match self {
                    $(Self::$variant => $byte),*
                }
            }

            pub const fn from_byte(byte: u8) -> Option<Self> {
                match byte {
                    $($byte => Some(Self::$variant),)*
                    _ => None,
                }
            }

            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text),*
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

opcode_group! {
    pub enum PushValue {
        Op0 => (0x00, "OP_0"),
        PushData1 => (0x4c, "OP_PUSHDATA1"),
        PushData2 => (0x4d, "OP_PUSHDATA2"),
        PushData4 => (0x4e, "OP_PUSHDATA4"),
        Op1Negate => (0x4f, "OP_1NEGATE"),
        OpReserved => (0x50, "OP_RESERVED"),
        Op1 => (0x51, "OP_1"),
        Op2 => (0x52, "OP_2"),
        Op3 => (0x53, "OP_3"),
        Op4 => (0x54, "OP_4"),
        Op5 => (0x55, "OP_5"),
        Op6 => (0x56, "OP_6"),
        Op7 => (0x57, "OP_7"),
        Op8 => (0x58, "OP_8"),
        Op9 => (0x59, "OP_9"),
        Op10 => (0x5a, "OP_10"),
        Op11 => (0x5b, "OP_11"),
        Op12 => (0x5c, "OP_12"),
        Op13 => (0x5d, "OP_13"),
        Op14 => (0x5e, "OP_14"),
        Op15 => (0x5f, "OP_15"),
        Op16 => (0x60, "OP_16"),
    }
}

// 别名,解决rust语法中，不同操作码对应相同字节码的问题
#[allow(non_upper_case_globals)]
impl PushValue {
    pub const OpFalse: Self = Self::Op0;
    pub const OpTrue: Self = Self::Op1;
}

opcode_group! {
    pub enum Control {
        OpNop => (0x61, "OP_NOP"),
        OpVer => (0x62, "OP_VER"),
        OpIf => (0x63, "OP_IF"),
        OpNotIf => (0x64, "OP_NOTIF"),
        OpVerIf => (0x65, "OP_VERIF"),
        OpVerNotIf => (0x66, "OP_VERNOTIF"),
        OpElse => (0x67, "OP_ELSE"),
        OpEndIf => (0x68, "OP_ENDIF"),
        OpVerify => (0x69, "OP_VERIFY"),
        OpReturn => (0x6a, "OP_RETURN"),
    }
}

opcode_group! {
    pub enum Stack {
        OpToAltStack => (0x6b, "OP_TOALTSTACK"),
        OpFromAltStack => (0x6c, "OP_FROMALTSTACK"),
        Op2Drop => (0x6d, "OP_2DROP"),
        Op2Dup => (0x6e, "OP_2DUP"),
        Op3Dup => (0x6f, "OP_3DUP"),
        Op2Over => (0x70, "OP_2OVER"),
        Op2Rot => (0x71, "OP_2ROT"),
        Op2Swap => (0x72, "OP_2SWAP"),
        OpIfDup => (0x73, "OP_IFDUP"),
        OpDepth => (0x74, "OP_DEPTH"),
        OpDrop => (0x75, "OP_DROP"),
        OpDup => (0x76, "OP_DUP"),
        OpNip => (0x77, "OP_NIP"),
        OpOver => (0x78, "OP_OVER"),
        OpPick => (0x79, "OP_PICK"),
        OpRoll => (0x7a, "OP_ROLL"),
        OpRot => (0x7b, "OP_ROT"),
        OpSwap => (0x7c, "OP_SWAP"),
        OpTuck => (0x7d, "OP_TUCK"),
    }
}

opcode_group! {
    pub enum Splice {
        OpCat => (0x7e, "OP_CAT"),
        OpSubStr => (0x7f, "OP_SUBSTR"),
        OpLeft => (0x80, "OP_LEFT"),
        OpRight => (0x81, "OP_RIGHT"),
        OpSize => (0x82, "OP_SIZE"),
    }
}

opcode_group! {
    pub enum BitLogic {
        OpInvert => (0x83, "OP_INVERT"),
        OpAnd => (0x84, "OP_AND"),
        OpOr => (0x85, "OP_OR"),
        OpXor => (0x86, "OP_XOR"),
        OpEqual => (0x87, "OP_EQUAL"),
        OpEqualVerify => (0x88, "OP_EQUALVERIFY"),
        OpReserved1 => (0x89, "OP_RESERVED1"),
        OpReserved2 => (0x8a, "OP_RESERVED2"),
    }
}

opcode_group! {
    pub enum Numeric {
        Op1Add => (0x8b, "OP_1ADD"),
        Op1Sub => (0x8c, "OP_1SUB"),
        Op2Mul => (0x8d, "OP_2MUL"),
        Op2Div => (0x8e, "OP_2DIV"),
        OpNegate => (0x8f, "OP_NEGATE"),
        OpAbs => (0x90, "OP_ABS"),
        OpNot => (0x91, "OP_NOT"),
        OpOp0NotEqual => (0x92, "OP_0NOTEQUAL"),
        OpAdd => (0x93, "OP_ADD"),
        OpSub => (0x94, "OP_SUB"),
        OpMul => (0x95, "OP_MUL"),
        OpDiv => (0x96, "OP_DIV"),
        OpMod => (0x97, "OP_MOD"),
        OpLShift => (0x98, "OP_LSHIFT"),
        OpRShift => (0x99, "OP_RSHIFT"),
        OpBoolAnd => (0x9a, "OP_BOOLAND"),
        OpBoolOr => (0x9b, "OP_BOOLOR"),
        OpNumEqual => (0x9c, "OP_NUMEQUAL"),
        OpNumEqualVerify => (0x9d, "OP_NUMEQUALVERIFY"),
        OpNumNotEqual => (0x9e, "OP_NUMNOTEQUAL"),
        OpLessThan => (0x9f, "OP_LESSTHAN"),
        OpGreaterThan => (0xa0, "OP_GREATERTHAN"),
        OpLessThanOrEqual => (0xa1, "OP_LESSTHANOREQUAL"),
        OpGreaterThanOrEqual => (0xa2, "OP_GREATERTHANOREQUAL"),
        OpMin => (0xa3, "OP_MIN"),
        OpMax => (0xa4, "OP_MAX"),
        OpWithin => (0xa5, "OP_WITHIN"),
    }
}

opcode_group! {
    pub enum Crypto {
        OpRipemd160 => (0xa6, "OP_RIPEMD160"),
        OpSha1 => (0xa7, "OP_SHA1"),
        OpSha256 => (0xa8, "OP_SHA256"),
        OpHash160 => (0xa9, "OP_HASH160"),
        OpHash256 => (0xaa, "OP_HASH256"),
        OpCodeSeparator => (0xab, "OP_CODESEPARATOR"),
        OpCheckSig => (0xac, "OP_CHECKSIG"),
        OpCheckSigVerify => (0xad, "OP_CHECKSIGVERIFY"),
        OpCheckMultiSig => (0xae, "OP_CHECKMULTISIG"),
        OpCheckMultiSigVerify => (0xaf, "OP_CHECKMULTISIGVERIFY"),
    }
}

opcode_group! {
    pub enum Expansion {
        OpNop1 => (0xb0, "OP_NOP1"),
        OpNop2 => (0xb1, "OP_NOP2"),
        OpNop3 => (0xb2, "OP_NOP3"),
        OpNop4 => (0xb3, "OP_NOP4"),
        OpNop5 => (0xb4, "OP_NOP5"),
        OpNop6 => (0xb5, "OP_NOP6"),
        OpNop7 => (0xb6, "OP_NOP7"),
        OpNop8 => (0xb7, "OP_NOP8"),
        OpNop9 => (0xb8, "OP_NOP9"),
        OpNop10 => (0xb9, "OP_NOP10"),
        OpCheckSigAdd => (0xba, "OP_CHECKSIGADD"),
    }
}

#[allow(non_upper_case_globals)]
impl Expansion {
    pub const OpCheckLockTimeVerify: Self = Self::OpNop2;
    pub const OpCheckSequenceVerify: Self = Self::OpNop3;
}

opcode_group! {
    pub enum Invalid {
        OpInvalidOpcode => (0xff, "OP_INVALIDOPCODE"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    Push(PushValue),
    Control(Control),
    Stack(Stack),
    Splice(Splice),
    BitLogic(BitLogic),
    Numeric(Numeric),
    Crypto(Crypto),
    Expansion(Expansion),
    Invalid(Invalid),
}

impl OpCode {
    pub const fn byte(self) -> u8 {
        match self {
            Self::Push(op) => op.byte(),
            Self::Control(op) => op.byte(),
            Self::Stack(op) => op.byte(),
            Self::Splice(op) => op.byte(),
            Self::BitLogic(op) => op.byte(),
            Self::Numeric(op) => op.byte(),
            Self::Crypto(op) => op.byte(),
            Self::Expansion(op) => op.byte(),
            Self::Invalid(op) => op.byte(),
        }
    }

    pub const fn from_byte(byte: u8) -> Option<Self> {
        if let Some(op) = PushValue::from_byte(byte) {
            return Some(Self::Push(op));
        }
        if let Some(op) = Control::from_byte(byte) {
            return Some(Self::Control(op));
        }
        if let Some(op) = Stack::from_byte(byte) {
            return Some(Self::Stack(op));
        }
        if let Some(op) = Splice::from_byte(byte) {
            return Some(Self::Splice(op));
        }
        if let Some(op) = BitLogic::from_byte(byte) {
            return Some(Self::BitLogic(op));
        }
        if let Some(op) = Numeric::from_byte(byte) {
            return Some(Self::Numeric(op));
        }
        if let Some(op) = Crypto::from_byte(byte) {
            return Some(Self::Crypto(op));
        }
        if let Some(op) = Expansion::from_byte(byte) {
            return Some(Self::Expansion(op));
        }
        if let Some(op) = Invalid::from_byte(byte) {
            return Some(Self::Invalid(op));
        }
        None
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Push(op) => op.as_str(),
            Self::Control(op) => op.as_str(),
            Self::Stack(op) => op.as_str(),
            Self::Splice(op) => op.as_str(),
            Self::BitLogic(op) => op.as_str(),
            Self::Numeric(op) => op.as_str(),
            Self::Crypto(op) => op.as_str(),
            Self::Expansion(op) => op.as_str(),
            Self::Invalid(op) => op.as_str(),
        }
    }
}

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
