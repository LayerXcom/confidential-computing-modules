use std::{
    prelude::v1::*,
    io::{self, Write, Read},
    net::{TcpStream as stdTcpStream, ToSocketAddrs},
    str
};
use crate::client::{create_client_config, TlsClient};
use crate::error::Result;
use mio::net::TcpStream as mioTcpStream;

pub struct HttpsClient(TlsClient);

const HTTPS_DEFAULT_PORT: u16 = 443;
const DEFAULT_EVENTS_CAPACITY: usize = 32;

impl HttpsClient {
    pub fn new(stream: stdTcpStream, hostname: &str) -> Result<Self> {
        let config = create_client_config()?;
        let socket = mioTcpStream::from_stream(stream)?;
        let client = TlsClient::new(socket, hostname, config)?;

        Ok(HttpsClient(client))
    }

    pub fn get(&self, req: &str) {
        unimplemented!();
    }

    pub fn post(&self, req: &str) {
        unimplemented!();
    }

    pub fn header(&self) {
        unimplemented!();
    }

    pub fn json(&self) {
        unimplemented!();
    }

    pub fn send(&self) {
        unimplemented!();
    }

    pub fn send_from_raw_req(&mut self, req: &str) -> Result<Vec<u8>> {
        self.0.write_all(req.as_bytes())?;
        let mut poll = mio::Poll::new()?;
        let mut events = mio::Events::with_capacity(DEFAULT_EVENTS_CAPACITY);
        self.0.register(&mut poll);
        let mut res = vec![];
        'outer: loop {
            poll.poll(&mut events, None)?;
            for ev in &events {
                if !self.0.ready(&mut poll, &ev, &mut res) {
                    break 'outer;
                }
            }
        }

        Ok(res)
    }
}


//
// temporary implementations
//

pub fn parse_response_attn_report(resp : &[u8]) -> (String, String, String){
	let mut headers = [httparse::EMPTY_HEADER; 16];
	let mut respp   = httparse::Response::new(&mut headers);
	let result = respp.parse(resp);

	let msg : &'static str;

	match respp.code {
		Some(200) => msg = "OK Operation Successful",
		Some(401) => msg = "Unauthorized Failed to authenticate or authorize request.",
		Some(404) => msg = "Not Found GID does not refer to a valid EPID group ID.",
		Some(500) => msg = "Internal error occurred",
		Some(503) => msg = "Service is currently not able to process the request (due to
			a temporary overloading or maintenance). This is a
			temporary state – the same request can be repeated after
			some time. ",
		_ => {println!("DBG:{}", respp.code.unwrap()); msg = "Unknown error occured"},
	}

	println!("    [Enclave] msg = {}", msg);
	let mut len_num : u32 = 0;

	let mut sig = String::new();
	let mut cert = String::new();
	let mut attn_report = String::new();

	for i in 0..respp.headers.len() {
		let h = respp.headers[i];
		match h.name{
			"Content-Length" => {
				let len_str = String::from_utf8(h.value.to_vec()).unwrap();
				len_num = len_str.parse::<u32>().unwrap();
			}
			"X-IASReport-Signature" => sig = str::from_utf8(h.value).unwrap().to_string(),
			"X-IASReport-Signing-Certificate" => cert = str::from_utf8(h.value).unwrap().to_string(),
			_ => (),
		}
	}

	// Remove %0A from cert, and only obtain the signing cert
	cert = cert.replace("%0A", "");
	cert = percent_decode(cert);
	let v: Vec<&str> = cert.split("-----").collect();
	let sig_cert = v[2].to_string();

	if len_num != 0 {
		let header_len = result.unwrap().unwrap();
		let resp_body = &resp[header_len..];
		attn_report = str::from_utf8(resp_body).unwrap().to_string();
	}

	// len_num == 0
	(attn_report, sig, sig_cert)
}

fn percent_decode(orig: String) -> String {
    let v:Vec<&str> = orig.split('%').collect();
    let mut ret = String::new();
    ret.push_str(v[0]);
    if v.len() > 1 {
        for s in v[1..].iter() {
            ret.push(u8::from_str_radix(&s[0..2], 16).unwrap() as char);
            ret.push_str(&s[2..]);
        }
    }
    ret
}

pub fn get_report_response(socket: &mut stdTcpStream, req: String) -> Result<Vec<u8>> {
    let config = create_client_config()?;
    let dns_name = webpki::DNSNameRef::try_from_ascii_str("api.trustedservices.intel.com")?;
    let mut sess = rustls::ClientSession::new(&config, dns_name);
    let mut tls = rustls::Stream::new(&mut sess, socket);
    tls.write_all(req.as_bytes())?;
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext)?;

    Ok(plaintext)
}
