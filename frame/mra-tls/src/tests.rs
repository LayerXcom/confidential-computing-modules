use crate::{Client, ClientConfig, RequestHandler, Server, ServerConfig};
use std::thread;

const ADDRESS: &str = "127.0.0.1:0";

#[derive(Default, Clone)]
struct EchoHandler;

impl RequestHandler for EchoHandler {
    fn handle<SE, DE>(&self, message: SE) -> Result<DE>
    where
        SE: Serialize,
        DE: DeserializeOwned,
    {
        let msg_json = serde_json::
    }
}

#[test]
fn test_request_response() {
    start_server();

    let msg = "Hello test_request_response";
    let client_config = ClientConfig::default();
    let mut client = Client::new(ADDRESS, client_config).unwrap();
    let resp = client.send_json(msg).unwrap();

    assert_eq!(msg, resp);
}

fn start_server() {
    let config = ServerConfig::default();
    let mut server = Server::new(ADDRESS.to_owned(), config);
    let handler = EchoHandler::default();
    thread::spawn(move || server.run(handler).unwrap())
}
