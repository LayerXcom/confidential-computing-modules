use crate::localstd::{
    io::{self, Read, Write},
    vec::Vec,
    string::String,
    convert::TryFrom,
};
use crate::{
    serde::{Serialize, Deserialize}
};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, SignatureError, SECRET_KEY_LENGTH};
use tiny_keccak::Keccak;
use codec::{Encode, Decode};
use anonify_types::{RawPubkey, RawSig, RawChallenge};
#[cfg(feature = "std")]
use rand::Rng;
#[cfg(feature = "std")]
use rand_core::{RngCore, CryptoRng};
#[cfg(feature = "std")]
use rand_os::OsRng;
use crate::local_anyhow::{anyhow, Error};

const ADDRESS_SIZE: usize = 20;

pub const COMMON_SECRET: [u8; SECRET_KEY_LENGTH] = [182, 93, 72, 157, 114, 225, 213, 95, 237, 176, 179, 23, 11, 100, 177, 16, 129, 8, 41, 4, 158, 209, 227, 21, 89, 47, 118, 0, 232, 162, 217, 203];
pub const COMMON_CHALLENGE: [u8; CHALLENGE_SIZE] = [39, 79, 228, 49, 240, 219, 135, 53, 169, 47, 65, 111, 236, 125, 2, 195, 214, 154, 18, 77, 254, 135, 35, 77, 36, 45, 164, 254, 64, 8, 169, 238];

/// Trait for 256-bits hash functions
pub trait Hash256 {
    fn hash(inp: &[u8]) -> Self;

    fn from_pubkey(pubkey: &PublicKey) -> Self;
}

/// User address represents last 20 bytes of digest of user's public key.
/// A signature verification must return true to generate a user address.
#[derive(Encode, Decode, Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct UserAddress([u8; ADDRESS_SIZE]);

#[cfg(feature = "std")]
impl From<UserAddress> for web3::types::Address {
    fn from(address: UserAddress) -> Self {
        let bytes = address.as_bytes();
        web3::types::Address::from_slice(bytes)
    }
}

#[cfg(feature = "std")]
impl From<&UserAddress> for web3::types::Address {
    fn from(address: &UserAddress) -> Self {
        let bytes = address.as_bytes();
        web3::types::Address::from_slice(bytes)
    }
}

impl From<&str> for UserAddress {
    fn from(s: &str) -> Self {
        let mut res = [0u8; ADDRESS_SIZE];
        res.copy_from_slice(&s.as_bytes()[..ADDRESS_SIZE]);

        Self::from_array(res)
    }
}

impl From<String> for UserAddress {
    fn from(s: String) -> Self {
        let mut res = [0u8; ADDRESS_SIZE];
        res.copy_from_slice(&s.as_bytes()[..ADDRESS_SIZE]);

        Self::from_array(res)
    }
}

impl TryFrom<Vec<u8>> for UserAddress {
    type Error = Error;

    fn try_from(s: Vec<u8>) -> Result<Self, Self::Error> {
        if s.len() < ADDRESS_SIZE {
            return Err(anyhow!("source length must be {}", ADDRESS_SIZE));
        }

        let mut res = [0u8; ADDRESS_SIZE];
        res.copy_from_slice(&s.as_slice()[..ADDRESS_SIZE]);
        Ok(Self::from_array(res))
    }
}

impl UserAddress {
    /// Get a user address only if the verification of signature returns true.
    pub fn from_sig(msg: &[u8], sig: &Signature, pubkey: &PublicKey) -> Result<Self, SignatureError> {
        pubkey.verify(msg, &sig)?;
        Ok(Self::from_pubkey(&pubkey))
    }

    pub fn from_access_right(access_right: &AccessRight) -> Result<Self, SignatureError> {
        access_right.verify_sig()?;
        Ok(Self::from_pubkey(access_right.pubkey()))
    }

    pub fn from_pubkey(pubkey: &PublicKey) -> Self {
        let hash = Sha256::from_pubkey(pubkey);
        let addr = &hash.as_array()[12..];
        let mut res = [0u8; ADDRESS_SIZE];
        res.copy_from_slice(addr);

        UserAddress(res)
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.0)?;
        Ok(())
    }

    pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut res = [0u8; ADDRESS_SIZE];
        reader.read_exact(&mut res)?;
        Ok(UserAddress(res))
    }

    #[cfg(feature = "std")]
    pub fn base64_encode(&self) -> String {
        base64::encode(self.as_bytes())
    }

    #[cfg(feature = "std")]
    pub fn base64_decode(encoded_str: &str) -> Self {
        let decoded_vec = base64::decode(encoded_str).expect("Failed to decode base64.");
        assert_eq!(decoded_vec.len(), ADDRESS_SIZE);

        let mut arr = [0u8; ADDRESS_SIZE];
        arr.copy_from_slice(&decoded_vec[..]);

        UserAddress::from_array(arr)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn from_array(array: [u8; ADDRESS_SIZE]) -> Self {
        UserAddress(array)
    }

    pub fn into_array(self) -> [u8; ADDRESS_SIZE] {
        self.0
    }
}

/// Hash digest of sha256 hash function
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash)]
pub struct Sha256([u8; 32]);

impl Hash256 for Sha256 {
    fn hash(inp: &[u8]) -> Self {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.input(inp);

        let mut res = Sha256::default();
        res.copy_from_slice(&hasher.result());
        res
    }

    fn from_pubkey(pubkey: &PublicKey) -> Self {
        Self::hash(&pubkey.to_bytes())
    }
}

impl Sha256 {
    pub fn as_array(&self) -> [u8; 32] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    fn copy_from_slice(&mut self, src: &[u8]) {
        self.0.copy_from_slice(src)
    }
}

/// A trait that will hash using Keccak256 the object it's implemented on.
pub trait Keccak256<T> {
    /// This will return a sized object with the hash
    fn keccak256(&self) -> T where T: Sized;
}

impl Keccak256<[u8; 32]> for [u8] {
    fn keccak256(&self) -> [u8; 32] {
        let mut keccak = Keccak::new_keccak256();
        let mut result = [0u8; 32];
        keccak.update(self);
        keccak.finalize(result.as_mut());
        result
    }
}

const CHALLENGE_SIZE: usize = 32;

/// Access right of Read/Write to anonify's enclave mem db.
#[derive(Debug, Clone)]
pub struct AccessRight {
    sig: Signature,
    pubkey: PublicKey,
    challenge: [u8; CHALLENGE_SIZE],
}

impl AccessRight {
    #[cfg(feature = "std")]
    fn inner_new_from_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let keypair = Keypair::generate(rng);
        let challenge = rand::thread_rng().gen::<[u8; 32]>();
        let sig = keypair.sign(&challenge);

        assert!(keypair.verify(&challenge, &sig).is_ok());

        Self::new(sig, keypair.public, challenge)
    }

    #[cfg(feature = "std")]
    pub fn new_from_rng() -> Result<Self, Error> {
        let mut csprng: OsRng = OsRng::new()?;
        Ok(Self::inner_new_from_rng(&mut csprng))
    }

    #[cfg(feature = "sgx")]
    pub fn new_from_rng() -> Result<Self, Error> {
        let mut seed = [0u8; SECRET_KEY_LENGTH];
        sgx_rand_assign(&mut seed)?;
        let secret = SecretKey::from_bytes(&seed)
            .map_err(|e| anyhow!("Failed to generate SecretKey: {:?}", e))?;

        let pubkey = PublicKey::from(&secret);
        let keypair = Keypair { secret, public: pubkey };

        let mut challenge = [0u8; CHALLENGE_SIZE];
        sgx_rand_assign(&mut challenge)?;
        let sig = keypair.sign(&challenge);

        assert!(keypair.verify(&challenge, &sig).is_ok());

        Ok(Self::new(sig, keypair.public, challenge))
    }

    pub fn new(
        sig: Signature,
        pubkey: PublicKey,
        challenge: [u8; 32],
    ) -> Self {
        assert!(pubkey.verify(&challenge, &sig).is_ok());

        AccessRight {
            sig,
            pubkey,
            challenge,
        }
    }

    pub fn verify_sig(&self) -> Result<(), SignatureError> {
        self.pubkey.verify(&self.challenge, &self.sig)?;
        Ok(())
    }

    pub fn user_address(&self) -> UserAddress {
        UserAddress::from_pubkey(&self.pubkey())
    }

    pub fn sig(&self) -> &Signature {
        &self.sig
    }

    pub fn pubkey(&self) -> &PublicKey {
        &self.pubkey
    }

    pub fn challenge(&self) -> &[u8] {
        &self.challenge
    }

    pub fn into_raw(self) -> (RawPubkey, RawSig, RawChallenge) {
        (self.pubkey().to_bytes(), self.sig().to_bytes(), self.challenge)
    }

    pub fn from_raw(
        raw_pubkey: RawPubkey,
        raw_sig: RawSig,
        raw_challenge: RawChallenge,
    ) -> Result<Self, SignatureError> {
        let sig = Signature::from_bytes(&raw_sig)?;
        let pubkey = PublicKey::from_bytes(&raw_pubkey)?;

        Ok(AccessRight::new(sig, pubkey, raw_challenge))
    }
}

pub trait IntoVec {
    fn into_vec(&self) -> Vec<u8>;
}

impl<T: IntoVec> IntoVec for Vec<T> {
    fn into_vec(&self) -> Vec<u8> {
        self.iter().fold(vec![], |mut acc, x| {
            acc.extend_from_slice(&x.into_vec());
            acc
        })
    }
}

impl<T: IntoVec> IntoVec for &[T] {
    fn into_vec(&self) -> Vec<u8> {
        self.iter().fold(vec![], |mut acc, x| {
            acc.extend_from_slice(&x.into_vec());
            acc
        })
    }
}

/// The size of initialization vector for AES-256-GCM.
pub const IV_SIZE: usize = 12;

const LOCK_PARAM_SIZE: usize = 32;

/// To avoid data collision when a transaction is sent to a blockchain.
#[derive(Encode, Decode, Clone, Copy, Debug, Default, PartialEq)]
pub struct LockParam([u8; LOCK_PARAM_SIZE]);

impl IntoVec for LockParam {
    fn into_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl LockParam {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), LOCK_PARAM_SIZE);
        let mut buf = [0u8; LOCK_PARAM_SIZE];
        buf.copy_from_slice(bytes);

        LockParam(buf)
    }

    pub fn from_bytes_iter(bytes: &[u8]) -> impl Iterator<Item=Self> + '_ {
        assert_eq!(bytes.len() % LOCK_PARAM_SIZE, 0);
        let iter_num = bytes.len() / LOCK_PARAM_SIZE;

        (0..iter_num).map(move |i| {
            let mut buf = [0u8; LOCK_PARAM_SIZE];
            let b = &bytes[i*LOCK_PARAM_SIZE..(i+1)*LOCK_PARAM_SIZE];
            buf.copy_from_slice(&b);
            LockParam(buf)
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.0)?;
        Ok(())
    }

    pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut res = [0u8; 32];
        reader.read_exact(&mut res)?;
        Ok(LockParam(res))
    }
}

impl From<Sha256> for LockParam {
    fn from(s: Sha256) -> Self {
        LockParam(s.as_array())
    }
}

/// Generating a random number inside the enclave.
#[cfg(feature = "sgx")]
pub fn sgx_rand_assign(rand: &mut [u8]) -> Result<(), Error> {
    use sgx_trts::trts::rsgx_read_rand;
    rsgx_read_rand(rand)
        .map_err(|e| anyhow!("error rsgx_read_rand: {:?}", e))?;
    Ok(())
}