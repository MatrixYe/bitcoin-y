use crate::block::{Block, BlockHeader};
use crate::errors::CError;
use crate::hash::Hash256;
use crate::tx::{OutPoint, Transaction, TxIn, TxOut};

pub fn serialize_compact_size(value: u64) -> Vec<u8> {
    let mut buffer = Vec::new();
    write_compact_size(&mut buffer, value);
    buffer
}

pub fn deserialize_compact_size(bytes: &[u8]) -> Result<(u64, usize), CError> {
    let mut reader = ByteReader::new(bytes);
    let value = reader.read_compact_size()?;
    Ok((value, reader.pos))
}

pub fn serialize_transaction(tx: &Transaction) -> Vec<u8> {
    let mut buffer = Vec::new();
    write_i32(&mut buffer, tx.version);
    write_compact_size(&mut buffer, tx.vin.len() as u64);
    for txin in &tx.vin {
        write_out_point(&mut buffer, &txin.prevout);
        write_var_bytes(&mut buffer, &txin.script_sig);
        write_u32(&mut buffer, txin.sequence);
    }

    write_compact_size(&mut buffer, tx.vout.len() as u64);
    for txout in &tx.vout {
        write_u64(&mut buffer, txout.value);
        write_var_bytes(&mut buffer, &txout.script_pubkey);
    }

    write_u32(&mut buffer, tx.lock_time);
    buffer
}

pub fn deserialize_transaction(bytes: &[u8]) -> Result<Transaction, CError> {
    let mut reader = ByteReader::new(bytes);
    let tx = read_transaction(&mut reader)?;
    reader.finish()?;
    Ok(tx)
}

pub fn serialize_block_header(header: &BlockHeader) -> [u8; 80] {
    let mut buffer = Vec::with_capacity(80);
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

pub fn deserialize_block_header(bytes: &[u8]) -> Result<BlockHeader, CError> {
    let mut reader = ByteReader::new(bytes);
    let header = read_block_header(&mut reader)?;
    reader.finish()?;
    Ok(header)
}

pub fn serialize_block(block: &Block) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&serialize_block_header(&block.header));
    write_compact_size(&mut buffer, block.txdata.len() as u64);
    for tx in &block.txdata {
        buffer.extend_from_slice(&serialize_transaction(tx));
    }
    buffer
}

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

fn read_transaction(reader: &mut ByteReader<'_>) -> Result<Transaction, CError> {
    let version = reader.read_i32()?;
    let input_count = reader.read_len()?;
    let mut vin = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        vin.push(TxIn {
            prevout: read_out_point(reader)?,
            script_sig: reader.read_var_bytes()?,
            sequence: reader.read_u32()?,
        });
    }

    let output_count = reader.read_len()?;
    let mut vout = Vec::with_capacity(output_count);
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

fn read_out_point(reader: &mut ByteReader<'_>) -> Result<OutPoint, CError> {
    Ok(OutPoint {
        hash: Hash256(reader.read_array::<32>()?),
        n: reader.read_u32()?,
    })
}

fn write_out_point(buffer: &mut Vec<u8>, out_point: &OutPoint) {
    buffer.extend_from_slice(&out_point.hash.0);
    write_u32(buffer, out_point.n);
}

fn write_var_bytes(buffer: &mut Vec<u8>, bytes: &[u8]) {
    write_compact_size(buffer, bytes.len() as u64);
    buffer.extend_from_slice(bytes);
}

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

fn write_i32(buffer: &mut Vec<u8>, value: i32) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(buffer: &mut Vec<u8>, value: u32) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(buffer: &mut Vec<u8>, value: u64) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

struct ByteReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

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

    fn read_len(&mut self) -> Result<usize, CError> {
        let value = self.read_compact_size()?;
        usize::try_from(value).map_err(|_| {
            CError::Parse(format!("CompactSize value {value} does not fit into usize"))
        })
    }

    fn read_var_bytes(&mut self) -> Result<Vec<u8>, CError> {
        let len = self.read_len()?;
        Ok(self.read_bytes(len)?.to_vec())
    }

    fn read_compact_size(&mut self) -> Result<u64, CError> {
        let first = self.read_u8()?;
        match first {
            0x00..=0xfc => Ok(first as u64),
            0xfd => {
                let value = u16::from_le_bytes(self.read_array::<2>()?) as u64;
                if value < 0xfd {
                    return Err(CError::Parse("Non-canonical CompactSize encoding".into()));
                }
                Ok(value)
            }
            0xfe => {
                let value = u32::from_le_bytes(self.read_array::<4>()?) as u64;
                if value <= 0xffff {
                    return Err(CError::Parse("Non-canonical CompactSize encoding".into()));
                }
                Ok(value)
            }
            0xff => {
                let value = u64::from_le_bytes(self.read_array::<8>()?);
                if value <= 0xffff_ffff {
                    return Err(CError::Parse("Non-canonical CompactSize encoding".into()));
                }
                Ok(value)
            }
        }
    }

    fn read_i32(&mut self) -> Result<i32, CError> {
        Ok(i32::from_le_bytes(self.read_array::<4>()?))
    }

    fn read_u32(&mut self) -> Result<u32, CError> {
        Ok(u32::from_le_bytes(self.read_array::<4>()?))
    }

    fn read_u64(&mut self) -> Result<u64, CError> {
        Ok(u64::from_le_bytes(self.read_array::<8>()?))
    }

    fn read_u8(&mut self) -> Result<u8, CError> {
        if self.pos >= self.bytes.len() {
            return Err(CError::Parse("Unexpected end of input".into()));
        }
        let value = self.bytes[self.pos];
        self.pos += 1;
        Ok(value)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], CError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| CError::Parse("Read length overflow".into()))?;
        if end > self.bytes.len() {
            return Err(CError::Parse(format!(
                "Unexpected end of input: need {len} bytes"
            )));
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], CError> {
        let bytes = self.read_bytes(N)?;
        let mut result = [0u8; N];
        result.copy_from_slice(bytes);
        Ok(result)
    }
}
