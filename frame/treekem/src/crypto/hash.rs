use codec::Encode;
use ring::digest::{Context, SHA256, Digest};

pub fn hash_encodable<E: Encode>(msg: &E) -> Digest {
    let buf = msg.encode();
    let mut ctx = Context::new(&SHA256);
    ctx.update(&buf);
    ctx.finish()
}
