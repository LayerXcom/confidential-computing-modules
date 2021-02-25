use ring::digest::{Context, Digest, SHA256};
use serde::Serialize;

pub fn hash_encodable<E: Serialize>(msg: &E) -> Digest {
    let buf = bincode::serialize(&msg).unwrap(); // must not fail
    let mut ctx = Context::new(&SHA256);
    ctx.update(&buf);
    ctx.finish()
}
