use crate::local_ring::digest::{Context, Digest, SHA256};
use codec::Encode;

pub fn hash_encodable<E: Encode>(msg: &E) -> Digest {
    let buf = msg.encode();
    let mut ctx = Context::new(&SHA256);
    ctx.update(&buf);
    ctx.finish()
}
