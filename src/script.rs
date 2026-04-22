// @Name: script
// @Date: 2026/4/13 09:55
// @Author: Matrix.Ye
// @Description:

pub type Script = Vec<u8>;
pub type CScript = Script;

// Script opcodes
pub enum OPCode {
    // 压栈
    Op0 = 0x00,
    // OpTrue  = Op1,
    // OpFalse = OP_0,
    OpPushData1 = 0x4c,
    OpPushData2 = 0x4d,
    OpPushData4 = 0x4e,
    Op1negate = 0x4f,
    OpReserved = 0x50,
    Op1 = 0x51,
    Op2 = 0x52,
    Op3 = 0x53,
    Op4 = 0x54,
    Op5 = 0x55,
    Op6 = 0x56,
    Op7 = 0x57,
    Op8 = 0x58,
    Op9 = 0x59,
    Op10 = 0x5a,
    Op11 = 0x5b,
    Op12 = 0x5c,
    Op13 = 0x5d,
    Op14 = 0x5e,
    Op15 = 0x5f,
    Op16 = 0x60,

    // 控制
    OpNop = 0x61,
    OpVer = 0x62,
    OpIf = 0x63,
    OpNotif = 0x64,
    OpVerif = 0x65,
    OpVernotif = 0x66,
    OpElse = 0x67,
    OpEndif = 0x68,
    OpVerify = 0x69,
    OpReturn = 0x6a,

    // 栈操作
    // stack ops
    OpToaltstack = 0x6b,
    OpLocalstack = 0x6c,
    Op2drop = 0x6d,
    Op2dup = 0x6e,
    Op3dup = 0x6f,
    Op2over = 0x70,
    Op2rot = 0x71,
    Op2swap = 0x72,
    OpDupin = 0x73,
    OpDepth = 0x74,
    OpDrop = 0x75,
    OpDup = 0x76,
    OpNip = 0x77,
    OpOver = 0x78,
    OpPick = 0x79,
    OpRoll = 0x7a,
    OpRot = 0x7b,
    OpSwap = 0x7c,
    OpTuck = 0x7d,
}
