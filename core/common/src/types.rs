
pub const STATE_SIZE: usize = 8;
pub const PUBKEY_SIZE: usize = 64;
pub const ADDRESS_SIZE: usize = 32;
pub const RANDOMNESS_SIZE: usize = 32;
pub const SIG_SIZE: usize = 65;
pub const CIPHERTEXT_SIZE: usize = ADDRESS_SIZE + STATE_SIZE + RANDOMNESS_SIZE;

pub type PubKey = [u8; PUBKEY_SIZE];
pub type Address = [u8; ADDRESS_SIZE];
pub type Value = u64;
pub type Randomness = [u8; RANDOMNESS_SIZE];
pub type Ciphertext = [u8; CIPHERTEXT_SIZE];
pub type Sig = [u8; SIG_SIZE];
pub type Msg = [u8; RANDOMNESS_SIZE];
