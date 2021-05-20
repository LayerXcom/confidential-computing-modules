use pgx::*;
use serde::{Deserialize, Serialize};

// StealthDB だと（サーバサイドのPostgreSQLが置いているクラウドを信用しない脅威モデルなので）
// Client Proxy がSQLに現れる integer を暗号化する。その際バイト列表現だとSQLが壊れるので
// Base64 エンコードしている。
//
// こちらのエクステンションではSQLに暗号文が現れるユースケースをサポートしないので、
// 直接暗号文のバイト列を保持できる。
#[derive(Serialize, Deserialize, PostgresType)]
pub struct EncInteger(Vec<u8>);

impl EncInteger {
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for EncInteger {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}
