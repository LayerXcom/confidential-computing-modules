use std::{
    prelude::v1::*,
    io::{self, Read, Write},
    sync::Arc,
};
use mio::{net::TcpStream, Ready, PollOpt};
use rustls::{ClientSession, ClientConfig, Session};
use crate::error::Result;

/// Setup a client token to allow us to identify the client event is for the socket.
const CLIENT: mio::Token = mio::Token(0);

/// A synchronous client to make requests with.
pub struct TlsClient {
    socket: TcpStream,
    session: rustls::ClientSession,
    is_closed: bool,
}

impl Write for TlsClient {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.session.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.session.flush()
    }
}

impl TlsClient {
    pub fn new(
        socket: TcpStream,
        hostname: &str,
        cfg: Arc<ClientConfig>
    ) -> Result<TlsClient> {
        let dns_name = webpki::DNSNameRef::try_from_ascii_str(hostname)?;

        Ok(TlsClient {
            socket,
            session: ClientSession::new(&cfg, dns_name),
            is_closed: false,
        })
    }

    pub fn ready(
        &mut self,
        poll: &mut mio::Poll,
        event: &mio::event::Event
    ) -> bool {
        assert_eq!(event.token(), CLIENT);

        if event.readiness().is_readable() {
            self.read_tls();
        }

        if event.readiness().is_writable() {
            self.write_tls();
        }

        if self.is_closed {
            println!("Connection closed.");
            return false;
        }

        if self.reregister(poll).is_err() {
            return false;
        };

        true
    }

    fn write_tls(&mut self) {
        if self.session.write_tls(&mut self.socket).is_err() {
            self.is_closed = true;
        }
    }

    fn read_tls(&mut self) {
        match self.session.read_tls(&mut self.socket) {
            Ok(0) => {
                println!("EOF; cleanly closed.");
                self.is_closed = true;
                return;
            },
            Err(e) => {
                println!("TLS Reading error: {:?}", e);
                self.is_closed = true;
                return;
            },
            _ => { },
        }

        if let Err(e) = self.session.process_new_packets() {
            println!("TLS Error: {:?}", e);
            self.is_closed = true;
            return;
        }

        let mut plaintext = vec![];
        if let Err(e) = self.session.read_to_end(&mut plaintext) {
            println!("Plaintext Reading error: {:?}", e);
            self.is_closed = true;
            return;
        }

        if !plaintext.is_empty() {
            io::stdout().write_all(&plaintext).unwrap();
        }
    }

    /// Register an `Evented` handle with the `Poll` instance.
    fn register(&self, poll: &mut mio::Poll) -> io::Result<()> {
        poll.register(
            &self.socket,
            CLIENT,
            self.ready_interest(),
            PollOpt::level() | PollOpt::oneshot()
        )
    }

    fn reregister(&self, poll: &mut mio::Poll) -> io::Result<()> {
        poll.reregister(
            &self.socket,
            CLIENT,
            self.ready_interest(),
            PollOpt::level() | PollOpt::oneshot()
        )
    }

    /// Use wants_read() and wants_write() to register for
    /// different mio-level I/O readiness events.
    fn ready_interest(&self) -> Ready {
        let wr = self.session.wants_read();
        let ww = self.session.wants_write();

        if wr && ww {
            Ready::readable() | Ready::writable()
        } else if wr {
            Ready::writable()
        } else {
            Ready::readable()
        }
    }
}



pub fn create_client_config(cert: &str) -> io::Result<Arc<ClientConfig>> {
    use std::{
        //Invoking ocall related functions that brings untrusted data into the trusted execution engine.
        untrusted::fs::File,
        io::BufReader,
    };
    use crate::cache::PersistCache;

    let mut config = ClientConfig::new();
    let certfile = File::open(cert)?;
    let mut reader = BufReader::new(certfile);
    config.root_store.add_pem_file(&mut reader).unwrap();

    let persist = Arc::new(PersistCache::new());
    config.set_persistence(persist);

    Ok(Arc::new(config))
}

