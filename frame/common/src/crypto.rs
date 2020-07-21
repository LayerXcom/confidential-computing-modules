use crate::localstd::{
    io::{self, Read, Write},
    vec::Vec,
    string::String,
    convert::TryFrom,
};
use crate::serde::{Serialize, Deserialize};
use crate::local_anyhow::{anyhow, Error};
use crate::traits::{IntoVec, Hash256};
use ed25519_dalek::{Keypair, SecretKey, PublicKey, Signature, SECRET_KEY_LENGTH, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use codec::{Encode, Decode, Input, self};
#[cfg(feature = "std")]
use rand::Rng;
#[cfg(feature = "std")]
use rand_core::{RngCore, CryptoRng};
#[cfg(feature = "std")]
use rand_os::OsRng;

const ADDRESS_SIZE: usize = 20;
pub const COMMON_SECRET: [u8; SECRET_KEY_LENGTH] = [182, 93, 72, 157, 114, 225, 213, 95, 237, 176, 179, 23, 11, 100, 177, 16, 129, 8, 41, 4, 158, 209, 227, 21, 89, 47, 118, 0, 232, 162, 217, 203];
pub const COMMON_CHALLENGE: [u8; CHALLENGE_SIZE] = [39, 79, 228, 49, 240, 219, 135, 53, 169, 47, 65, 111, 236, 125, 2, 195, 214, 154, 18, 77, 254, 135, 35, 77, 36, 45, 164, 254, 64, 8, 169, 238];

lazy_static! {
    pub static ref COMMON_ACCESS_RIGHT: AccessRight = {
        let secret = SecretKey::from_bytes(&COMMON_SECRET).unwrap();
        let pubkey = PublicKey::from(&secret);
        let keypair = Keypair { secret, public: pubkey };

        let sig = keypair.sign(&COMMON_CHALLENGE);

        assert!(keypair.verify(&COMMON_CHALLENGE, &sig).is_ok());
        AccessRight::new(sig, keypair.public, COMMON_CHALLENGE)
    };

    pub static ref OWNER_ADDRESS: UserAddress = {
        COMMON_ACCESS_RIGHT.user_address()
    };
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
    pub fn from_sig(msg: &[u8], sig: &Signature, pubkey: &PublicKey) -> Result<Self, Error> {
        pubkey.verify(msg, &sig)
            .map_err(|e| anyhow!("{}", e))?;

        Ok(Self::from_pubkey(&pubkey))
    }

    pub fn from_access_right(access_right: &AccessRight) -> Result<Self, Error> {
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

/// Generating a random number inside the enclave.
#[cfg(feature = "sgx")]
pub fn sgx_rand_assign(rand: &mut [u8]) -> Result<(), Error> {
    use sgx_trts::trts::rsgx_read_rand;
    rsgx_read_rand(rand)
        .map_err(|e| anyhow!("error rsgx_read_rand: {:?}", e))?;
    Ok(())
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
    pub fn new(hash: [u8; 32]) -> Self {
        Sha256(hash)
    }

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

const CHALLENGE_SIZE: usize = 32;

/// Access right of Read/Write to anonify's enclave mem db.
#[derive(Debug, Clone)]
pub struct AccessRight {
    sig: Signature,
    pubkey: PublicKey,
    challenge: [u8; CHALLENGE_SIZE],
}

// impl AccessControl for AccessRight {
//     fn is_allowed(self) -> Result<(), Error> {
//         self.verify_sig()
//             .map_err(|e| anyhow!("{}", e))
//     }
// }

impl Encode for AccessRight {
    fn encode(&self) -> Vec<u8> {
        let mut acc = vec![];
        acc.extend_from_slice(&self.sig.to_bytes());
        acc.extend_from_slice(self.pubkey.as_bytes());
        acc.extend_from_slice(&self.challenge[..]);

        acc
    }
}

impl Decode for AccessRight {
    fn decode<I: Input>(value: &mut I) -> Result<Self, codec::Error> {
        let mut sig_buf = [0u8; SIGNATURE_LENGTH];
        let mut pubkey_buf = [0u8; PUBLIC_KEY_LENGTH];
        let mut chal_buf = [0u8; CHALLENGE_SIZE];

        value.read(&mut sig_buf)?;
        value.read(&mut pubkey_buf)?;
        value.read(&mut chal_buf)?;

        let sig = Signature::from_bytes(&sig_buf)
            .expect("Failed to decode sig of AccessRight");
        let pubkey = PublicKey::from_bytes(&pubkey_buf)
            .expect("Failed to decode pubkey of AccessRight");

        Ok(AccessRight{
            sig,
            pubkey,
            challenge: chal_buf,
        })
    }
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
        use ed25519_dalek::{SecretKey, SECRET_KEY_LENGTH};

        let mut seed = [0u8; SECRET_KEY_LENGTH];
        sgx_rand_assign(&mut seed)?;
        let secret = SecretKey::from_bytes(&seed)
            .expect("invalid secret key length");

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

    pub fn verify_sig(&self) -> Result<(), Error> {
        self.pubkey.verify(&self.challenge, &self.sig)
            .map_err(|e| anyhow!("{:?}", e))?;

        Ok(())
    }

    pub fn user_address(&self) -> UserAddress {
        UserAddress::from_pubkey(&self.pubkey())
    }

    pub fn verified_user_address(&self) -> Result<UserAddress, Error> {
        self.verify_sig()?;
        Ok(UserAddress::from_pubkey(&self.pubkey()))
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


/// Application message broadcasted to other members.
#[derive(Clone, Debug, Encode, Decode)]
pub struct Ciphertext {
    generation: u32,
    epoch: u32,
    roster_idx: u32,
    encrypted_state: Vec<u8>,
}

impl Ciphertext {
    pub fn new(generation: u32, epoch: u32, roster_idx: u32, encrypted_state: Vec<u8>) -> Self {
        Ciphertext { generation, epoch, roster_idx, encrypted_state }
    }

    pub fn from_bytes(bytes: &mut [u8], len: usize) -> Self {
        assert_eq!(bytes.len(), len);
        Ciphertext::decode(&mut &bytes[..]).unwrap()
    }

    pub fn as_vec(&self) -> Vec<u8> {
        self.encode()
    }

    pub fn generation(&self) -> u32 {
        self.generation
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    pub fn roster_idx(&self) -> u32 {
        self.roster_idx
    }

    pub fn encrypted_state_ref(&self) -> &[u8] {
        &self.encrypted_state
    }
}

impl IntoVec for Ciphertext {
    fn into_vec(&self) -> Vec<u8> {
        self.encode()
    }
}
