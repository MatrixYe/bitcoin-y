use crate::bignum::BigNum;
use crate::script::consts::MAX_SCRIPT_SIZE;
use crate::script::opcode::{BitLogic, Crypto, OpCode, PushValue, Stack};
use crate::script::{Script, ScriptError};
use crate::wallet::key::PubKey;

/// @Name: builder
///
/// @Date: 2026/6/11 16:50
///
/// @Author: Matrix.Ye
///
/// @Description: 脚本构造器
/// Push 编码规则
///
/// ```text
/// 长度 0              -> OP_0
/// 长度 1..=75         -> `[长度字节]` + data
/// 长度 76..=255       -> OP_PUSHDATA1 + u8长度 + data
/// 长度 256..=65535    -> OP_PUSHDATA2 + u16小端长度 + data
/// 更长                -> OP_PUSHDATA4 + u32小端长度 + data
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScriptBuilder {
    data: Script,
}

/// 标准脚本模板的最小集合。
///
/// 当前先覆盖 v0.3.19 挖矿和普通转账最核心的 P2PK/P2PKH，后续可继续补充 multisig。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StandardScript {
    /// `<pubkey> OP_CHECKSIG`
    PayToPubKey { pubkey: Vec<u8> },
    /// `OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG`
    PayToPubKeyHash { pubkey_hash: [u8; 20] },
    /// 无法识别为当前支持的标准模板。
    NonStandard,
}

impl ScriptBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// 使用能够表达数据长度的最短 push 编码写入字节串
    pub fn push_bytes(&mut self, bytes: &[u8]) -> Result<&mut Self, ScriptError> {
        let prefix_len = match bytes.len() {
            0 | 1..=0x4b => 1,
            0x4c..=0xff => 2,
            0x100..=0xffff => 3,
            _ => 5,
        };
        self.ensure_can_append(prefix_len, bytes.len())?;

        match bytes.len() {
            0 => self.data.push(PushValue::Op0.byte()),
            len @ 1..=0x4b => self.data.push(len as u8),
            len @ 0x4c..=0xff => {
                self.data.push(PushValue::PushData1.byte());
                self.data.push(len as u8);
            }
            len @ 0x100..=0xffff => {
                self.data.push(PushValue::PushData2.byte());
                self.data.extend_from_slice(&(len as u16).to_le_bytes());
            }
            len => {
                let len = u32::try_from(len).map_err(|_| ScriptError::PushDataLengthTooLarge {
                    kind: "OP_PUSHDATA4",
                    max: u32::MAX as usize,
                    actual: len,
                })?;
                self.data.push(PushValue::PushData4.byte());
                self.data.extend_from_slice(&len.to_le_bytes());
            }
        }

        self.data.extend_from_slice(bytes);
        Ok(self)
    }

    /// 将 UTF-8 字符串作为普通脚本数据写入
    pub fn push_str(&mut self, string: &str) -> Result<&mut Self, ScriptError> {
        self.push_bytes(string.as_bytes())
    }

    /// 使用 Bitcoin ScriptNum 的符号-绝对值格式写入大整数
    pub fn push_script_num(&mut self, num: &BigNum) -> Result<&mut Self, ScriptError> {
        self.push_bytes(&num.to_bytes_le())
    }

    /// 写入一个已经由类型系统验证的操作码
    pub fn push_opcode(&mut self, opcode: OpCode) -> Result<&mut Self, ScriptError> {
        self.ensure_can_append(1, 0)?;
        self.data.push(opcode.byte());
        Ok(self)
    }

    /// 完成构造并移交脚本所有权
    pub fn into_script(self) -> Result<Script, ScriptError> {
        Ok(self.data)
    }

    fn ensure_can_append(&self, prefix_len: usize, data_len: usize) -> Result<(), ScriptError> {
        let actual = self
            .data
            .len()
            .checked_add(prefix_len)
            .and_then(|len| len.checked_add(data_len))
            .unwrap_or(usize::MAX);

        // 最大10_000
        if actual > MAX_SCRIPT_SIZE {
            Err(ScriptError::ScriptTooLarge {
                max: MAX_SCRIPT_SIZE,
                actual,
            })
        } else {
            Ok(())
        }
    }
}

impl StandardScript {
    /// 构造早期 coinbase 常用的 P2PK 脚本：`<pubkey> OP_CHECKSIG`。
    pub fn p2pk(pubkey: PubKey) -> Result<Script, ScriptError> {
        let mut builder = ScriptBuilder::new();
        builder
            .push_bytes(&pubkey.to_bytes())?
            .push_opcode(OpCode::Crypto(Crypto::OpCheckSig))?;
        builder.into_script()
    }

    /// 构造经典 P2PKH 脚本：`OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG`。
    pub fn p2pkh(pubkey_hash: [u8; 20]) -> Result<Script, ScriptError> {
        let mut builder = ScriptBuilder::new();
        builder
            .push_opcode(OpCode::Stack(Stack::OpDup))?
            .push_opcode(OpCode::Crypto(Crypto::OpHash160))?
            .push_bytes(&pubkey_hash)?
            .push_opcode(OpCode::BitLogic(BitLogic::OpEqualVerify))?
            .push_opcode(OpCode::Crypto(Crypto::OpCheckSig))?;
        builder.into_script()
    }

    /// 识别当前支持的标准脚本模板。
    ///
    /// 这里按最短 push 编码识别 P2PKH；P2PK 同时接受压缩公钥和未压缩公钥。
    pub fn parse(script: &[u8]) -> Self {
        parse_p2pk(script)
            .or_else(|| parse_p2pkh(script))
            .unwrap_or(Self::NonStandard)
    }
}

fn parse_p2pk(script: &[u8]) -> Option<StandardScript> {
    let pubkey_len = script.first().copied()? as usize;
    let is_pubkey_len = pubkey_len == 33 || pubkey_len == 65;
    let is_script_len = script.len() == pubkey_len + 2;
    let is_checksig = script.last().copied() == Some(Crypto::OpCheckSig.byte());

    (is_pubkey_len && is_script_len && is_checksig).then(|| StandardScript::PayToPubKey {
        pubkey: script[1..1 + pubkey_len].to_vec(),
    })
}

fn parse_p2pkh(script: &[u8]) -> Option<StandardScript> {
    const P2PKH_LEN: usize = 25;

    let is_p2pkh = script.len() == P2PKH_LEN
        && script[0] == Stack::OpDup.byte()
        && script[1] == Crypto::OpHash160.byte()
        && script[2] == 20
        && script[23] == BitLogic::OpEqualVerify.byte()
        && script[24] == Crypto::OpCheckSig.byte();

    is_p2pkh.then(|| {
        let mut pubkey_hash = [0u8; 20];
        pubkey_hash.copy_from_slice(&script[3..23]);
        StandardScript::PayToPubKeyHash { pubkey_hash }
    })
}
