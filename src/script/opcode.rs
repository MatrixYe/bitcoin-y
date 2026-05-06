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
/// 3. 多个名称对应同一字节时，用关联常量表达别名。
///
/// 关于分组的解释：Bitcoin Script 的共识要求是：脚本按字节流解释，每条指令从一个字节开始。
/// 这个字节对应某种 opcode 或 push-data 前缀。
/// 至于源码里把这些 opcode 放在一个大 enum，还是拆成多个分组 enum，是实现层面的选择。
///但是我的目标是学习和理解脚本系统，不只是机械翻译 C++。
/// C++ 里 flat enum 加注释已经够用，因为它的解释器主要靠 switch(opcode)。
/// 但 Rust 的 enum 可以表达结构，把注释里的分类变成类型，可以让后续代码更清楚
/// 而且分组能减少解释器里的辅助判断，一些辅助方法`is_push`,`is_control`就不用再写了，
/// rust的匹配模式非常强大，很好用
use std::fmt;


/// ## 操作码表,取自比特币维基百科
///
/// ### PushOp
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
/// ### ControlOp
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
/// ### StackOp
///
/// | 操作码 | 字节码 | 原版名称 | 功能 |
/// | --- | --- | --- | --- |
/// | `ToAltStack` | `0x6b` | `OP_TOALTSTACK` | 将主栈栈顶移动到备用栈 |
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
/// ### SpliceOp
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
/// ### BitLogicOp
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
/// ### NumericOp
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
/// ### CryptoOp
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
/// ### ExpansionOp
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
/// ### InvalidOp
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
    pub enum PushOp {
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
impl PushOp {
    pub const OpFalse: Self = Self::Op0;
    pub const OpTrue: Self = Self::Op1;
}

opcode_group! {
    pub enum ControlOp {
        Nop => (0x61, "OP_NOP"),
        Ver => (0x62, "OP_VER"),
        If => (0x63, "OP_IF"),
        NotIf => (0x64, "OP_NOTIF"),
        VerIf => (0x65, "OP_VERIF"),
        VerNotIf => (0x66, "OP_VERNOTIF"),
        Else => (0x67, "OP_ELSE"),
        EndIf => (0x68, "OP_ENDIF"),
        Verify => (0x69, "OP_VERIFY"),
        Return => (0x6a, "OP_RETURN"),
    }
}

opcode_group! {
    pub enum StackOp {
        ToAltStack => (0x6b, "OP_TOALTSTACK"),
        FromAltStack => (0x6c, "OP_FROMALTSTACK"),
        Op2Drop => (0x6d, "OP_2DROP"),
        Op2Dup => (0x6e, "OP_2DUP"),
        Op3Dup => (0x6f, "OP_3DUP"),
        Op2Over => (0x70, "OP_2OVER"),
        Op2Rot => (0x71, "OP_2ROT"),
        Op2Swap => (0x72, "OP_2SWAP"),
        IfDup => (0x73, "OP_IFDUP"),
        Depth => (0x74, "OP_DEPTH"),
        Drop => (0x75, "OP_DROP"),
        Dup => (0x76, "OP_DUP"),
        Nip => (0x77, "OP_NIP"),
        Over => (0x78, "OP_OVER"),
        Pick => (0x79, "OP_PICK"),
        Roll => (0x7a, "OP_ROLL"),
        Rot => (0x7b, "OP_ROT"),
        Swap => (0x7c, "OP_SWAP"),
        Tuck => (0x7d, "OP_TUCK"),
    }
}

opcode_group! {
    pub enum SpliceOp {
        Cat => (0x7e, "OP_CAT"),
        SubStr => (0x7f, "OP_SUBSTR"),
        Left => (0x80, "OP_LEFT"),
        Right => (0x81, "OP_RIGHT"),
        Size => (0x82, "OP_SIZE"),
    }
}

opcode_group! {
    pub enum BitLogicOp {
        Invert => (0x83, "OP_INVERT"),
        And => (0x84, "OP_AND"),
        Or => (0x85, "OP_OR"),
        Xor => (0x86, "OP_XOR"),
        Equal => (0x87, "OP_EQUAL"),
        EqualVerify => (0x88, "OP_EQUALVERIFY"),
        Reserved1 => (0x89, "OP_RESERVED1"),
        Reserved2 => (0x8a, "OP_RESERVED2"),
    }
}

opcode_group! {
    pub enum NumericOp {
        Op1Add => (0x8b, "OP_1ADD"),
        Op1Sub => (0x8c, "OP_1SUB"),
        Op2Mul => (0x8d, "OP_2MUL"),
        Op2Div => (0x8e, "OP_2DIV"),
        Negate => (0x8f, "OP_NEGATE"),
        Abs => (0x90, "OP_ABS"),
        Not => (0x91, "OP_NOT"),
        Op0NotEqual => (0x92, "OP_0NOTEQUAL"),
        Add => (0x93, "OP_ADD"),
        Sub => (0x94, "OP_SUB"),
        Mul => (0x95, "OP_MUL"),
        Div => (0x96, "OP_DIV"),
        Mod => (0x97, "OP_MOD"),
        LShift => (0x98, "OP_LSHIFT"),
        RShift => (0x99, "OP_RSHIFT"),
        BoolAnd => (0x9a, "OP_BOOLAND"),
        BoolOr => (0x9b, "OP_BOOLOR"),
        NumEqual => (0x9c, "OP_NUMEQUAL"),
        NumEqualVerify => (0x9d, "OP_NUMEQUALVERIFY"),
        NumNotEqual => (0x9e, "OP_NUMNOTEQUAL"),
        LessThan => (0x9f, "OP_LESSTHAN"),
        GreaterThan => (0xa0, "OP_GREATERTHAN"),
        LessThanOrEqual => (0xa1, "OP_LESSTHANOREQUAL"),
        GreaterThanOrEqual => (0xa2, "OP_GREATERTHANOREQUAL"),
        Min => (0xa3, "OP_MIN"),
        Max => (0xa4, "OP_MAX"),
        Within => (0xa5, "OP_WITHIN"),
    }
}

opcode_group! {
    pub enum CryptoOp {
        Ripemd160 => (0xa6, "OP_RIPEMD160"),
        Sha1 => (0xa7, "OP_SHA1"),
        Sha256 => (0xa8, "OP_SHA256"),
        Hash160 => (0xa9, "OP_HASH160"),
        Hash256 => (0xaa, "OP_HASH256"),
        CodeSeparator => (0xab, "OP_CODESEPARATOR"),
        CheckSig => (0xac, "OP_CHECKSIG"),
        CheckSigVerify => (0xad, "OP_CHECKSIGVERIFY"),
        CheckMultiSig => (0xae, "OP_CHECKMULTISIG"),
        CheckMultiSigVerify => (0xaf, "OP_CHECKMULTISIGVERIFY"),
    }
}

opcode_group! {
    pub enum ExpansionOp {
        Nop1 => (0xb0, "OP_NOP1"),
        Nop2 => (0xb1, "OP_NOP2"),
        Nop3 => (0xb2, "OP_NOP3"),
        Nop4 => (0xb3, "OP_NOP4"),
        Nop5 => (0xb4, "OP_NOP5"),
        Nop6 => (0xb5, "OP_NOP6"),
        Nop7 => (0xb6, "OP_NOP7"),
        Nop8 => (0xb7, "OP_NOP8"),
        Nop9 => (0xb8, "OP_NOP9"),
        Nop10 => (0xb9, "OP_NOP10"),
        CheckSigAdd => (0xba, "OP_CHECKSIGADD"),
    }
}

#[allow(non_upper_case_globals)]
impl ExpansionOp {
    pub const CheckLockTimeVerify: Self = Self::Nop2;
    pub const CheckSequenceVerify: Self = Self::Nop3;
}

opcode_group! {
    pub enum InvalidOp {
        InvalidOpcode => (0xff, "OP_INVALIDOPCODE"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    Push(PushOp),
    Control(ControlOp),
    Stack(StackOp),
    Splice(SpliceOp),
    BitLogic(BitLogicOp),
    Numeric(NumericOp),
    Crypto(CryptoOp),
    Expansion(ExpansionOp),
    Invalid(InvalidOp),
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
        if let Some(op) = PushOp::from_byte(byte) {
            return Some(Self::Push(op));
        }
        if let Some(op) = ControlOp::from_byte(byte) {
            return Some(Self::Control(op));
        }
        if let Some(op) = StackOp::from_byte(byte) {
            return Some(Self::Stack(op));
        }
        if let Some(op) = SpliceOp::from_byte(byte) {
            return Some(Self::Splice(op));
        }
        if let Some(op) = BitLogicOp::from_byte(byte) {
            return Some(Self::BitLogic(op));
        }
        if let Some(op) = NumericOp::from_byte(byte) {
            return Some(Self::Numeric(op));
        }
        if let Some(op) = CryptoOp::from_byte(byte) {
            return Some(Self::Crypto(op));
        }
        if let Some(op) = ExpansionOp::from_byte(byte) {
            return Some(Self::Expansion(op));
        }
        if let Some(op) = InvalidOp::from_byte(byte) {
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
