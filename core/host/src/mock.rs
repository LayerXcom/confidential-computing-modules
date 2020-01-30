use std::{
    io::{self, Read, Write},
    ops::{Add, Sub},
};
use serde::{Serialize, Deserialize};
use byteorder::{ByteOrder, LittleEndian};
use anonify_common::State;

const MOCK_STATE_LENGTH: usize = 8;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Serialize, Deserialize)]
pub struct MockState(u64);

impl State for MockState {
    fn new(init: u64) -> Self {
        MockState(init)
    }

    fn as_bytes(&self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(MOCK_STATE_LENGTH);
        self.write_le(&mut buf)?;
        Ok(buf)
    }

    fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let mut buf = bytes;
        Self::read_le(&mut buf)
    }

    fn write_le<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let mut buf = [0u8; MOCK_STATE_LENGTH];
        LittleEndian::write_u64(&mut buf, self.0);
        writer.write_all(&buf)?;

        Ok(())
    }

    fn read_le<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; MOCK_STATE_LENGTH];
        reader.read_exact(&mut buf)?;
        let res = LittleEndian::read_u64(&buf);

        Ok(MockState(res))
    }
}

impl Add for MockState {
    type Output = MockState;

    fn add(self, other: Self) -> Self {
        let res = self.0 + other.0;
        MockState(res)
    }
}

impl Sub for MockState {
    type Output = MockState;

    fn sub(self, other: Self) -> Self {
        let res = self.0 - other.0;
        MockState(res)
    }
}

impl MockState {
    pub fn into_raw(&self) -> u64 {
        self.0
    }
}
