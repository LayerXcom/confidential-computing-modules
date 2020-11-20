use crate::connection::Connection;

pub struct Client<S: rustls::Session> {
    connection: Connection<S>
}

impl<S: rustls::Session> Client<S> {
    pub fn new() -> Self {
        unimplemented!();
    }

    pub fn request() {
        unimplemented!();
    }
}