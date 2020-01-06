use crate::localstd::{
    io::{self, Read, Write},
    vec::Vec,
};

/// Trait of each user's state.
pub trait State: Sized + Default {
    fn new(init: u64) -> Self;

    fn as_bytes(&self) -> io::Result<Vec<u8>>;

    fn write_le<W: Write>(&self, writer: &mut W) -> io::Result<()>;

    fn read_le<R: Read>(reader: &mut R) -> io::Result<Self>;
}
