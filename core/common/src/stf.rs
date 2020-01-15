use crate::State;
use crate::localstd::{
    io::{self, Read, Write, Error, ErrorKind},
    ops::{Add, Sub},
    vec::Vec,
};
use byteorder::{ByteOrder, LittleEndian};
#[cfg(feature = "sgx")]
use serde_sgx::{Deserialize, Serialize};
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

const VALUE_LENGTH: usize = 8;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Serialize, Deserialize)]
pub struct Value(u64);

impl State for Value {
    fn new(init: u64) -> Self {
        Value(init)
    }

    fn as_bytes(&self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(VALUE_LENGTH);
        LittleEndian::write_u64(&mut buf, self.0);

        if buf.len() != VALUE_LENGTH {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid Value length."));
        }

        Ok(buf)
    }

    fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != VALUE_LENGTH {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid Value length."));
        }

        let res = LittleEndian::read_u64(bytes);
        Ok(Value(res))
    }

    fn write_le<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let mut buf = [0u8; 8];
        LittleEndian::write_u64(&mut buf, self.0);
        writer.write_all(&buf)?;

        Ok(())
    }

    fn read_le<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf)?;
        let res = LittleEndian::read_u64(&buf);

        Ok(Value(res))
    }
}

impl Add for Value {
    type Output = Value;

    fn add(self, other: Self) -> Self {
        let res = self.0 + other.0;
        Value(res)
    }
}

impl Sub for Value {
    type Output = Value;

    fn sub(self, other: Self) -> Self {
        let res = self.0 - other.0;
        Value(res)
    }
}

impl Value {
    pub fn into_raw_u64(&self) -> u64 {
        self.0
    }
}
