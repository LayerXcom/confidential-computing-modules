// anonify-enclave
pub const MY_ROSTER_IDX: usize = 0;
pub const MAX_ROSTER_IDX: usize = 2;
pub const UNTIL_ROSTER_IDX: usize = 10;
pub const UNTIL_EPOCH: usize = 30;
pub const IAS_URL: &str = "https://api.trustedservices.intel.com/sgx/dev/attestation/v3/report";
pub const MRA_TLS_SERVER_ADDRESS: &str = "localhost:12345";

// backup
pub const DEFAULT_LOCAL_PATH_SECRETS_DIR: &str = ".anonify/pathsecrets";

// commands
pub const ENCRYPT_COMMAND_CMD: u32 = 1;
pub const INSERT_CIPHERTEXT_CMD: u32 = 2;
pub const INSERT_HANDSHAKE_CMD: u32 = 3;
pub const GET_STATE_CMD: u32 = 4;
pub const CALL_JOIN_GROUP_CMD: u32 = 5;
pub const CALL_HANDSHAKE_CMD: u32 = 6;
pub const REGISTER_NOTIFICATION_CMD: u32 = 7;
pub const GET_ENCRYPTING_KEY_CMD: u32 = 8;
pub const CALL_REGISTER_REPORT_CMD: u32 = 9;
pub const START_SERVER_CMD: u32 = 10;
pub const STOP_SERVER_CMD: u32 = 11;
