//! 脚本系统 操作码
use std::fmt;

/// @Name: opcode
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
/// 而且分组能减少解释器里的辅助判断，一些辅助方法`is_push`,`is_control`就不用再写了，rust的匹配模式非常强大，很好用

// 宏：操作码分组
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

// 别名是
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
