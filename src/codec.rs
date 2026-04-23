use crate::block::{Block, BlockHeader};
use crate::errors::CError;
use crate::hash::Hash256;
use crate::transaction::{OutPoint, Transaction, TxIn, TxOut};

/// @Name: codec
///
/// @Date: 2026/4/19 03:41
///
/// @Author: Matrix.Ye
///
/// @Description: 编码和解码，序列化与反序列化

/// 将整数编码为 Bitcoin CompactSize 格式。
pub fn serialize_compact_size(value: u64) -> Vec<u8> {
    let mut buffer = Vec::new();
    write_compact_size(&mut buffer, value);
    buffer
}

/// 从字节切片读取一个 CompactSize 值，并返回已消耗字节数。
pub fn deserialize_compact_size(bytes: &[u8]) -> Result<(u64, usize), CError> {
    let mut reader = ByteReader::new(bytes);
    let value = reader.read_compact_size()?;
    Ok((value, reader.pos))
}

/// 按传统 Bitcoin 共识格式序列化交易。不考虑隔离见证
pub fn serialize_transaction(tx: &Transaction) -> Vec<u8> {
    let mut buffer = Vec::new();

    // version
    write_i32(&mut buffer, tx.version);
    // 输入列表 vin
    write_compact_size(&mut buffer, tx.vin.len() as u64);
    for txin in &tx.vin {
        write_out_point(&mut buffer, &txin.prevout);
        write_var_bytes(&mut buffer, &txin.script_sig);
        write_u32(&mut buffer, txin.sequence);
    }

    // 输出列表 vout
    write_compact_size(&mut buffer, tx.vout.len() as u64);
    for txout in &tx.vout {
        write_u64(&mut buffer, txout.value);
        write_var_bytes(&mut buffer, &txout.script_pubkey);
    }
    // lock_time
    write_u32(&mut buffer, tx.lock_time);
    buffer
}

/// 反序列化一笔完整交易，要求输入字节全部被消费。
pub fn deserialize_transaction(bytes: &[u8]) -> Result<Transaction, CError> {
    let mut reader = ByteReader::new(bytes);
    let tx = read_transaction(&mut reader)?;
    reader.finish()?;
    Ok(tx)
}

/// 序列化 80 字节区块头。
pub fn serialize_block_header(header: &BlockHeader) -> [u8; 80] {
    let mut buffer = Vec::with_capacity(80);

    // 区块头字段固定长度，总计 80 字节。
    write_i32(&mut buffer, header.version);
    buffer.extend_from_slice(&header.prev_block.0);
    buffer.extend_from_slice(&header.merkle_root.0);
    write_u32(&mut buffer, header.time);
    write_u32(&mut buffer, header.bits);
    write_u32(&mut buffer, header.nonce);
    buffer
        .try_into()
        .expect("block header serialization must be 80 bytes")
}

/// 反序列化一个完整区块头，要求输入恰好为一个区块头。
pub fn deserialize_block_header(bytes: &[u8]) -> Result<BlockHeader, CError> {
    let mut reader = ByteReader::new(bytes);
    let header = read_block_header(&mut reader)?;
    reader.finish()?;
    Ok(header)
}

/// 按传统 Bitcoin 共识格式序列化区块。
pub fn serialize_block(block: &Block) -> Vec<u8> {
    let mut buffer = Vec::new();

    // 区块 = 区块头 + 交易数量 + 交易列表。
    buffer.extend_from_slice(&serialize_block_header(&block.header));
    write_compact_size(&mut buffer, block.txdata.len() as u64);
    for tx in &block.txdata {
        buffer.extend_from_slice(&serialize_transaction(tx));
    }
    buffer
}

/// 反序列化一个完整区块，要求输入字节全部被消费。
pub fn deserialize_block(bytes: &[u8]) -> Result<Block, CError> {
    let mut reader = ByteReader::new(bytes);
    let header = read_block_header(&mut reader)?;
    let tx_count = reader.read_len()?;
    let mut txdata = Vec::with_capacity(tx_count);
    for _ in 0..tx_count {
        txdata.push(read_transaction(&mut reader)?);
    }
    reader.finish()?;
    Ok(Block { header, txdata })
}

/// 从当前游标位置读取一笔交易。
fn read_transaction(reader: &mut ByteReader<'_>) -> Result<Transaction, CError> {
    let version = reader.read_i32()?;
    let input_count = reader.read_len()?;
    let mut vin = Vec::with_capacity(input_count);

    // 输入数量由 CompactSize 指定。
    for _ in 0..input_count {
        vin.push(TxIn {
            prevout: read_out_point(reader)?,
            script_sig: reader.read_var_bytes()?,
            sequence: reader.read_u32()?,
        });
    }

    let output_count = reader.read_len()?;
    let mut vout = Vec::with_capacity(output_count);

    // 输出数量由 CompactSize 指定。
    for _ in 0..output_count {
        vout.push(TxOut {
            value: reader.read_u64()?,
            script_pubkey: reader.read_var_bytes()?,
        });
    }

    Ok(Transaction {
        version,
        vin,
        vout,
        lock_time: reader.read_u32()?,
    })
}

/// 从当前游标位置读取 80 字节区块头。
fn read_block_header(reader: &mut ByteReader<'_>) -> Result<BlockHeader, CError> {
    Ok(BlockHeader {
        version: reader.read_i32()?,
        prev_block: Hash256(reader.read_array::<32>()?),
        merkle_root: Hash256(reader.read_array::<32>()?),
        time: reader.read_u32()?,
        bits: reader.read_u32()?,
        nonce: reader.read_u32()?,
    })
}

/// 从当前游标位置读取交易输出点。
fn read_out_point(reader: &mut ByteReader<'_>) -> Result<OutPoint, CError> {
    Ok(OutPoint {
        hash: Hash256(reader.read_array::<32>()?),
        n: reader.read_u32()?,
    })
}

/// 写入交易输出点。
fn write_out_point(buffer: &mut Vec<u8>, out_point: &OutPoint) {
    buffer.extend_from_slice(&out_point.hash.0);
    write_u32(buffer, out_point.n);
}

/// 写入 CompactSize 长度前缀和原始字节。
fn write_var_bytes(buffer: &mut Vec<u8>, bytes: &[u8]) {
    write_compact_size(buffer, bytes.len() as u64);
    buffer.extend_from_slice(bytes);
}

/// 写入 Bitcoin CompactSize 编码。
///Raw交易格式和几个同行 对等 网络消息使用可变长度整数来指示后续数据中的字节数。
/// 参考链接[比特币开发者：紧凑型无符号整数](https://bitcoindevelopers.org/docs/reference/transactions-ref/#raw-transaction-format)
fn write_compact_size(buffer: &mut Vec<u8>, value: u64) {
    match value {
        0..=0xfc => buffer.push(value as u8),
        0xfd..=0xffff => {
            buffer.push(0xfd);
            buffer.extend_from_slice(&(value as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            buffer.push(0xfe);
            buffer.extend_from_slice(&(value as u32).to_le_bytes());
        }
        _ => {
            buffer.push(0xff);
            buffer.extend_from_slice(&value.to_le_bytes());
        }
    }
}

/// 写入 i32 小端整数。
fn write_i32(buffer: &mut Vec<u8>, value: i32) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

/// 写入 u32 小端整数。
fn write_u32(buffer: &mut Vec<u8>, value: u32) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

/// 写入 u64 小端整数。
fn write_u64(buffer: &mut Vec<u8>, value: u64) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

/// 带游标的字节读取器。
struct ByteReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    /// 创建读取器，游标从 0 开始。
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// 确认所有输入字节都已被消费。
    fn finish(&self) -> Result<(), CError> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(CError::Parse(format!(
                "Trailing bytes after decode: {}",
                self.bytes.len() - self.pos
            )))
        }
    }

    /// 读取 CompactSize 并转换为 usize 长度。
    fn read_len(&mut self) -> Result<usize, CError> {
        let value = self.read_compact_size()?;
        usize::try_from(value).map_err(|_| {
            CError::Parse(format!("CompactSize value {value} does not fit into usize"))
        })
    }

    /// 读取带 CompactSize 长度前缀的字节数组。
    fn read_var_bytes(&mut self) -> Result<Vec<u8>, CError> {
        let len = self.read_len()?;
        Ok(self.read_bytes(len)?.to_vec())
    }

    /// 读取 Bitcoin CompactSize 编码。
    fn read_compact_size(&mut self) -> Result<u64, CError> {
        let first = self.read_u8()?;
        match first {
            0x00..=0xfc => Ok(first as u64),
            0xfd => {
                let value = u16::from_le_bytes(self.read_array::<2>()?) as u64;
                // Bitcoin 要求 CompactSize 使用最短编码。
                if value < 0xfd {
                    return Err(CError::Parse("Non-canonical CompactSize encoding".into()));
                }
                Ok(value)
            }
            0xfe => {
                let value = u32::from_le_bytes(self.read_array::<4>()?) as u64;
                // 防止把较小值编码进较长分支。
                if value <= 0xffff {
                    return Err(CError::Parse("Non-canonical CompactSize encoding".into()));
                }
                Ok(value)
            }
            0xff => {
                let value = u64::from_le_bytes(self.read_array::<8>()?);
                // 防止把 u32 范围内的值编码为 8 字节。
                if value <= 0xffff_ffff {
                    return Err(CError::Parse("Non-canonical CompactSize encoding".into()));
                }
                Ok(value)
            }
        }
    }

    /// 读取 i32 小端整数。
    fn read_i32(&mut self) -> Result<i32, CError> {
        Ok(i32::from_le_bytes(self.read_array::<4>()?))
    }

    /// 读取 u32 小端整数。
    fn read_u32(&mut self) -> Result<u32, CError> {
        Ok(u32::from_le_bytes(self.read_array::<4>()?))
    }

    /// 读取 u64 小端整数。
    fn read_u64(&mut self) -> Result<u64, CError> {
        Ok(u64::from_le_bytes(self.read_array::<8>()?))
    }

    /// 读取单个字节。
    fn read_u8(&mut self) -> Result<u8, CError> {
        if self.pos >= self.bytes.len() {
            return Err(CError::Parse("Unexpected end of input".into()));
        }
        let value = self.bytes[self.pos];
        self.pos += 1;
        Ok(value)
    }

    /// 读取指定长度的字节切片。
    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], CError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| CError::Parse("Read length overflow".into()))?;
        // 任何越界读取都视为输入截断。
        if end > self.bytes.len() {
            return Err(CError::Parse(format!(
                "Unexpected end of input: need {len} bytes"
            )));
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// 读取固定长度数组。
    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], CError> {
        let bytes = self.read_bytes(N)?;
        let mut result = [0u8; N];
        result.copy_from_slice(bytes);
        Ok(result)
    }
}
