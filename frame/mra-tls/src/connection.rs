

pub struct Connection<S: rustls::Session> {
    stream: rustls::StreamOwned<S, std::net::TcpStream>,
}

impl<S: rustls::Session> Connection<S> {
    pub fn new() -> Self {
        unimplemented!();
    }

    pub fn read_frame() {
        unimplemented!();
    }

    pub fn write_frame() {
        unimplemented!();
    }
}
