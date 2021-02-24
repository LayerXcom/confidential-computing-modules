use crate::bincode;
use crate::local_anyhow::{anyhow, Error};
use crate::local_once_cell::sync::Lazy;
use crate::localstd::{
    boxed::Box,
    cmp::Ordering,
    fmt,
    io::{self, Read, Write},
    string::String,
    vec::Vec,
};
use crate::serde::{Deserialize, Serialize};
use crate::serde_big_array::big_array;
use crate::serde_bytes;
use crate::traits::{AccessPolicy, Hash256, IntoVec, StateDecoder};
use ed25519_dalek::{
    Keypair, PublicKey, SecretKey, Signature, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
    SIGNATURE_LENGTH,
};
#[cfg(feature = "std")]
use rand::Rng;
#[cfg(feature = "std")]
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "std")]
use rand_os::OsRng;
use sha2::Digest;

const ACCOUNT_ID_SIZE: usize = 20;
pub const COMMON_SECRET: [u8; SECRET_KEY_LENGTH] = [
    182, 93, 72, 157, 114, 225, 213, 95, 237, 176, 179, 23, 11, 100, 177, 16, 129, 8, 41, 4, 158,
    209, 227, 21, 89, 47, 118, 0, 232, 162, 217, 203,
];
pub const COMMON_CHALLENGE: [u8; CHALLENGE_SIZE] = [
    39, 79, 228, 49, 240, 219, 135, 53, 169, 47, 65, 111, 236, 125, 2, 195, 214, 154, 18, 77, 254,
    135, 35, 77, 36, 45, 164, 254, 64, 8, 169, 238,
];

pub static COMMON_ACCESS_POLICY: Lazy<Ed25519ChallengeResponse> = Lazy::new(|| {
    let secret = SecretKey::from_bytes(&COMMON_SECRET).unwrap();
    let pubkey = PublicKey::from(&secret);
    let keypair = Keypair {
        secret,
        public: pubkey,
    };

    let sig = keypair.sign(&COMMON_CHALLENGE);

    assert!(keypair.verify(&COMMON_CHALLENGE, &sig).is_ok());
    Ed25519ChallengeResponse::new(sig, keypair.public, COMMON_CHALLENGE)
});
pub static OWNER_ACCOUNT_ID: Lazy<AccountId> = Lazy::new(|| COMMON_ACCESS_POLICY.account_id());

/// User account_id represents last 20 bytes of digest of user's public key.
/// A signature verification must return true to generate a user account_id.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(crate = "crate::serde")]
pub struct AccountId(pub [u8; ACCOUNT_ID_SIZE]);

#[cfg(feature = "std")]
impl From<AccountId> for web3::types::Address {
    fn from(account_id: AccountId) -> Self {
        let bytes = account_id.as_bytes();
        web3::types::Address::from_slice(bytes)
    }
}

#[cfg(feature = "std")]
impl From<&AccountId> for web3::types::Address {
    fn from(account_id: &AccountId) -> Self {
        let bytes = account_id.as_bytes();
        web3::types::Address::from_slice(bytes)
    }
}

impl From<&str> for AccountId {
    fn from(s: &str) -> Self {
        let mut res = [0u8; ACCOUNT_ID_SIZE];
        res.copy_from_slice(&s.as_bytes()[..ACCOUNT_ID_SIZE]);

        Self::from_array(res)
    }
}

impl From<String> for AccountId {
    fn from(s: String) -> Self {
        let mut res = [0u8; ACCOUNT_ID_SIZE];
        res.copy_from_slice(&s.as_bytes()[..ACCOUNT_ID_SIZE]);

        Self::from_array(res)
    }
}

impl StateDecoder for AccountId {
    fn decode_vec(v: Vec<u8>) -> Result<Self, Error> {
        if v.len() < ACCOUNT_ID_SIZE {
            return Err(anyhow!("source length must be {}", ACCOUNT_ID_SIZE));
        }

        let mut res = [0u8; ACCOUNT_ID_SIZE];
        res.copy_from_slice(&v.as_slice()[..ACCOUNT_ID_SIZE]);
        Ok(Self::from_array(res))
    }

    fn decode_mut_bytes(b: &mut [u8]) -> Result<Self, Error> {
        if b.len() < ACCOUNT_ID_SIZE {
            return Err(anyhow!("source length must be {}", ACCOUNT_ID_SIZE));
        }

        let mut res = [0u8; ACCOUNT_ID_SIZE];
        res.copy_from_slice(&b[..ACCOUNT_ID_SIZE]);
        Ok(Self::from_array(res))
    }
}

impl AccountId {
    /// Get a user account_id only if the verification of signature returns true.
    pub fn from_sig(msg: &[u8], sig: &Signature, pubkey: &PublicKey) -> Result<Self, Error> {
        pubkey.verify(msg, &sig).map_err(|e| anyhow!("{}", e))?;

        Ok(Self::from_pubkey(&pubkey))
    }

    pub fn try_from_access_policy<AP: AccessPolicy>(access_policy: &AP) -> Result<Self, Error> {
        access_policy.verify()?;
        Ok(access_policy.into_account_id())
    }

    pub fn from_access_policy<AP: AccessPolicy>(access_policy: &AP) -> Self {
        access_policy.into_account_id()
    }

    pub fn from_pubkey(pubkey: &PublicKey) -> Self {
        let hash = Sha256::from_pubkey(pubkey);
        let account_id = &hash.as_array()[12..];
        let mut res = [0u8; ACCOUNT_ID_SIZE];
        res.copy_from_slice(account_id);

        AccountId(res)
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.0)?;
        Ok(())
    }

    pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut res = [0u8; ACCOUNT_ID_SIZE];
        reader.read_exact(&mut res)?;
        Ok(AccountId(res))
    }

    #[cfg(feature = "std")]
    pub fn base64_encode(&self) -> String {
        base64::encode(self.as_bytes())
    }

    #[cfg(feature = "std")]
    pub fn base64_decode(encoded_str: &str) -> Self {
        let decoded_vec = base64::decode(encoded_str).expect("Failed to decode base64.");
        assert_eq!(decoded_vec.len(), ACCOUNT_ID_SIZE);

        let mut arr = [0u8; ACCOUNT_ID_SIZE];
        arr.copy_from_slice(&decoded_vec[..]);

        AccountId::from_array(arr)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn from_array(array: [u8; ACCOUNT_ID_SIZE]) -> Self {
        AccountId(array)
    }

    pub fn into_array(self) -> [u8; ACCOUNT_ID_SIZE] {
        self.0
    }
}

/// Generating a random number inside the enclave.
#[cfg(feature = "sgx")]
pub fn rand_assign(rand: &mut [u8]) -> Result<(), Error> {
    use sgx_trts::trts::rsgx_read_rand;
    rsgx_read_rand(rand).map_err(|e| anyhow!("error rsgx_read_rand: {:?}", e))?;
    Ok(())
}

#[cfg(feature = "std")]
pub fn rand_assign(rand: &mut [u8]) -> Result<(), Error> {
    let mut csprng: OsRng = OsRng::new()?;
    csprng.fill_bytes(rand);
    Ok(())
}

/// Hash digest of sha256 hash function
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash)]
pub struct Sha256([u8; 32]);

impl Hash256 for Sha256 {
    fn hash(inp: &[u8]) -> Self {
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

    pub fn hash_for_attested_tx(
        ciphertext: &[u8],
        roster_idx: u32,
        generation: u32,
        epoch: u32,
    ) -> Self {
        let mut hasher = sha2::Sha256::new();
        hasher.input(ciphertext);
        hasher.input(roster_idx.to_be_bytes());
        hasher.input(generation.to_be_bytes());
        hasher.input(epoch.to_be_bytes());

        let mut res = Sha256::default();
        res.copy_from_slice(&hasher.result());
        res
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

/// No authentication when evaluating an access policy.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(crate = "crate::serde")]
pub struct NoAuth {
    account_id: AccountId,
}

impl AccessPolicy for NoAuth {
    fn verify(&self) -> Result<(), Error> {
        Ok(())
    }

    fn into_account_id(&self) -> AccountId {
        self.account_id
    }
}

impl NoAuth {
    pub fn new(account_id: AccountId) -> Self {
        NoAuth { account_id }
    }

    pub fn account_id(&self) -> AccountId {
        self.account_id
    }
}

big_array! { BigArray; }

/// A challenge and response authentication parameter to read and write to anonify's enclave mem db.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct Ed25519ChallengeResponse {
    #[serde(with = "BigArray")]
    sig: [u8; SIGNATURE_LENGTH],
    pubkey: [u8; PUBLIC_KEY_LENGTH],
    challenge: [u8; CHALLENGE_SIZE],
}

impl Default for Ed25519ChallengeResponse {
    fn default() -> Self {
        Self {
            sig: [0u8; SIGNATURE_LENGTH],
            pubkey: [0u8; PUBLIC_KEY_LENGTH],
            challenge: [0u8; CHALLENGE_SIZE],
        }
    }
}

impl AccessPolicy for Ed25519ChallengeResponse {
    fn verify(&self) -> Result<(), Error> {
        self.verify_sig()
    }

    fn into_account_id(&self) -> AccountId {
        AccountId::from_pubkey(&self.pubkey())
    }
}

impl Ed25519ChallengeResponse {
    #[cfg(feature = "std")]
    pub fn new_from_keypair<R: Rng>(keypair: Keypair, rng: &mut R) -> Self {
        let challenge: [u8; 32] = rng.gen();
        let sig = keypair.sign(&challenge[..]);
        assert!(keypair.verify(&challenge, &sig).is_ok());

        Self::new(sig, keypair.public, challenge)
    }

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
        rand_assign(&mut seed)?;
        let secret = SecretKey::from_bytes(&seed).expect("invalid secret key length");

        let pubkey = PublicKey::from(&secret);
        let keypair = Keypair {
            secret,
            public: pubkey,
        };

        let mut challenge = [0u8; CHALLENGE_SIZE];
        rand_assign(&mut challenge)?;
        let sig = keypair.sign(&challenge);

        assert!(keypair.verify(&challenge, &sig).is_ok());

        Ok(Self::new(sig, keypair.public, challenge))
    }

    pub fn new(sig: Signature, pubkey: PublicKey, challenge: [u8; 32]) -> Self {
        assert!(pubkey.verify(&challenge, &sig).is_ok());

        Ed25519ChallengeResponse {
            sig: sig.to_bytes(),
            pubkey: pubkey.to_bytes(),
            challenge,
        }
    }

    pub fn new_from_bytes(
        sig: [u8; SIGNATURE_LENGTH],
        pubkey: [u8; PUBLIC_KEY_LENGTH],
        challenge: [u8; CHALLENGE_SIZE],
    ) -> Self {
        Self {
            sig,
            pubkey,
            challenge,
        }
    }

    pub fn verify_sig(&self) -> Result<(), Error> {
        self.pubkey()
            .verify(&self.challenge, &self.sig())
            .map_err(|e| anyhow!("{:?}", e))?;

        Ok(())
    }

    pub fn account_id(&self) -> AccountId {
        AccountId::from_pubkey(&self.pubkey())
    }

    pub fn verified_account_id(&self) -> Result<AccountId, Error> {
        self.verify_sig()?;
        Ok(AccountId::from_pubkey(&self.pubkey()))
    }

    pub fn sig(&self) -> Signature {
        Signature::from_bytes(&self.sig).unwrap()
    }

    pub fn pubkey(&self) -> PublicKey {
        PublicKey::from_bytes(&self.pubkey).unwrap()
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
#[derive(Clone, Serialize, Deserialize, Eq, Ord, Hash, Default)]
#[serde(crate = "crate::serde")]
pub struct Ciphertext {
    generation: u32,
    epoch: u32,
    roster_idx: u32,
    #[serde(with = "serde_bytes")]
    encrypted_state: Vec<u8>,
}

impl fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Ciphertext {{ generation: {:?}, epoch: {:?}, roster_idx: {:?}, encrypted_state: 0x{} }}",
            self.generation(),
            self.epoch(),
            self.roster_idx(),
            hex::encode(&self.encrypted_state)
        )
    }
}

impl PartialEq for Ciphertext {
    fn eq(&self, other: &Ciphertext) -> bool {
        self.roster_idx() == other.roster_idx()
            && self.generation() == other.generation()
            && self.epoch() == other.epoch()
    }
}

/// Ordering by priority of roster_idx, epoch, generation
impl PartialOrd for Ciphertext {
    fn partial_cmp(&self, other: &Ciphertext) -> Option<Ordering> {
        let roster_idx_ord = self.roster_idx().partial_cmp(&other.roster_idx())?;
        if roster_idx_ord != Ordering::Equal {
            return Some(roster_idx_ord);
        }

        let epoch_ord = self.epoch().partial_cmp(&other.epoch())?;
        if epoch_ord != Ordering::Equal {
            return Some(epoch_ord);
        }

        let gen_ord = self.generation().partial_cmp(&other.generation())?;
        if gen_ord != Ordering::Equal {
            return Some(gen_ord);
        }

        Some(Ordering::Equal)
    }
}

impl Ciphertext {
    pub fn new(generation: u32, epoch: u32, roster_idx: u32, encrypted_state: Vec<u8>) -> Self {
        Ciphertext {
            generation,
            epoch,
            roster_idx,
            encrypted_state,
        }
    }

    pub fn decode(bytes: &[u8]) -> crate::localstd::result::Result<Self, Box<bincode::ErrorKind>> {
        bincode::deserialize(&bytes[..])
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap() // must not fail
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

// Calculated by `SgxSealedData<PathSecret>::calc_raw_sealed_data_size(add_mac_txt_size: u32, encrypt_txt_size: u32) -> u32`
pub const SEALED_DATA_SIZE: usize = 592;
pub const EXPORT_ID_SIZE: usize = 32;
pub const EXPORT_PATH_SECRET_SIZE: usize = SEALED_DATA_SIZE + 4 + EXPORT_ID_SIZE + 2; // added 2 bytes by encoding

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(crate = "crate::serde")]
pub struct ExportPathSecret {
    #[serde(with = "serde_bytes")]
    encoded_sealed: Vec<u8>,
    epoch: u32,
    id: [u8; EXPORT_ID_SIZE], // Unique identifier of path secret
}

impl ExportPathSecret {
    pub fn new(encoded_sealed: Vec<u8>, epoch: u32, id: [u8; EXPORT_ID_SIZE]) -> Self {
        assert_eq!(id.len(), 32);
        ExportPathSecret {
            encoded_sealed,
            epoch,
            id,
        }
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    pub fn encoded_sealed(&self) -> &[u8] {
        &self.encoded_sealed[..]
    }

    pub fn id(&self) -> [u8; EXPORT_ID_SIZE] {
        self.id
    }

    pub fn id_as_ref(&self) -> &[u8] {
        &self.id[..]
    }
}

/// Handshake parameter for exporting outside enclave
#[derive(Clone, Serialize, Deserialize, Hash, Default)]
#[serde(crate = "crate::serde")]
pub struct ExportHandshake {
    prior_epoch: u32,
    roster_idx: u32,
    #[serde(with = "serde_bytes")]
    handshake: Vec<u8>,
}

impl fmt::Debug for ExportHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ExportHandshake {{ prior_epoch: {:?}, roster_idx: {:?}, handshake: 0x{} }}",
            self.prior_epoch,
            self.roster_idx,
            hex::encode(&self.handshake)
        )
    }
}

impl ExportHandshake {
    pub fn new(prior_epoch: u32, roster_idx: u32, handshake: Vec<u8>) -> Self {
        ExportHandshake {
            prior_epoch,
            roster_idx,
            handshake,
        }
    }

    pub fn prior_epoch(&self) -> u32 {
        self.prior_epoch
    }

    pub fn roster_idx(&self) -> u32 {
        self.roster_idx
    }

    pub fn handshake(&self) -> &[u8] {
        &self.handshake[..]
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap() // must not fail
    }

    pub fn decode(bytes: &[u8]) -> crate::localstd::result::Result<Self, Box<bincode::ErrorKind>> {
        bincode::deserialize(bytes)
    }
}
