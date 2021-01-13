// filepath
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
