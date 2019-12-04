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
        event: &mio::event::Event,
        buf: &mut Vec<u8>,
    ) -> bool {
        assert_eq!(event.token(), CLIENT);

        if event.readiness().is_readable() {
            self.read_tls(buf);
        }

        if event.readiness().is_writable() {
            self.write_tls();
        }

        if self.is_closed {
            println!("Connection closed.");
            return false;
        }

        self.reregister(poll);
        true
    }

    fn write_tls(&mut self) {
        if self.session.write_tls(&mut self.socket).is_err() {
            self.is_closed = true;
        }
    }

    fn read_tls(&mut self, buf: &mut Vec<u8>) {
        // match self.session.read_tls(&mut self.socket) {
        //     Ok(0) => {
        //         println!("EOF; cleanly closed.");
        //         self.is_closed = true;
        //         return;
        //     },
        //     Err(e) => {
        //         println!("TLS Reading error: {:?}", e);
        //         self.is_closed = true;
        //         return;
        //     },
        //     _ => { },
        // }

        // if let Err(e) = self.session.process_new_packets() {
        //     println!("TLS Error: {:?}", e);
        //     self.is_closed = true;
        //     return;
        // }

        // if let Err(e) = self.session.read_to_end(buf) {
        //     println!("Plaintext Reading error: {:?}", e);
        //     self.is_closed = true;
        //     return;
        // }

        // Read TLS data.  This fails if the underlying TCP connection
        // is broken.
        let rc = self.session.read_tls(&mut self.socket);
        if rc.is_err() {
            println!("TLS read error: {:?}", rc);
            self.is_closed = true;
            return;
        }

        // If we're ready but there's no data: EOF.
        if rc.unwrap() == 0 {
            println!("EOF");
            self.is_closed = true;
            return;
        }

        // Reading some TLS data might have yielded new TLS
        // messages to process.  Errors from this indicate
        // TLS protocol problems and are fatal.
        let processed = self.session.process_new_packets();
        if processed.is_err() {
            println!("TLS error: {:?}", processed.unwrap_err());
            self.is_closed = true;
            return;
        }

        // Having read some TLS data, and processed any new messages,
        // we might have new plaintext as a result.
        //
        // Read it and then write it to stdout.
        let mut plaintext = Vec::new();
        let rc = self.session.read_to_end(&mut plaintext);
        if !plaintext.is_empty() {
            io::stdout().write_all(&plaintext).unwrap();
        }

        // If that fails, the peer might have started a clean TLS-level
        // session closure.
        if rc.is_err() {
            let err = rc.unwrap_err();
            println!("Plaintext read error: {:?}", err);
            self.is_closed = true;
            return;
        }
    }

    /// Register an `Evented` handle with the `Poll` instance.
    pub fn register(&self, poll: &mut mio::Poll) {
        println!("register");
        poll.register(
            &self.socket,
            CLIENT,
            self.ready_interest(),
            PollOpt::level() | PollOpt::oneshot()
        ).unwrap()
    }

    fn reregister(&self, poll: &mut mio::Poll) {
        println!("reregister");
        poll.reregister(
            &self.socket,
            CLIENT,
            self.ready_interest(),
            PollOpt::level() | PollOpt::oneshot()
        ).unwrap()
    }

    /// Use wants_read() and wants_write() to register for
    /// different mio-level I/O readiness events.
    fn ready_interest(&self) -> Ready {
        let wants_read = self.session.wants_read();
        let wants_write = self.session.wants_write();

        if wants_read && wants_write {
            Ready::readable() | Ready::writable()
        } else if wants_write {
            Ready::writable()
        } else {
            Ready::readable()
        }
    }
}

pub fn create_client_config() -> io::Result<Arc<ClientConfig>> {
    use std::{
        //Invoking ocall related functions that brings untrusted data into the trusted execution engine.
        untrusted::fs::File,
        io::BufReader,
    };
    use crate::cache::PersistCache;

    let mut config = ClientConfig::new();
    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    // let certfile = File::open(cert_path)?;
    // let mut reader = BufReader::new(certfile);
    // config.root_store.add_pem_file(&mut reader).unwrap();

    let persist = Arc::new(PersistCache::new());
    config.set_persistence(persist);

    Ok(Arc::new(config))
}

