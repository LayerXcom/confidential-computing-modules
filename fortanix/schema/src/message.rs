/// A Message type to communication between enclave and host
#[derive(Serialize, Deserialize, Debug)]
pub struct EnclaveMessage {
    /// Unique message identifier
    id: u64,
    /// Request or Respone
    message_type: MessageType,
    /// Data body of the message
    body: Body,
    /// Tracing context serialized in binary format
    #[serde(with = "serde_bytes")]
    span_context: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
// #[repr(u8)]
pub enum MessageType {
    Request = 0,
    Response = 1,
}

impl serde::Serialize for MessageType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(*self as u8)
    }
}

impl<'de> serde::Deserialize<'de> for MessageType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match u8::deserialize(deserializer)? {
            0 => Ok(MessageType::Request),
            1 => Ok(MessageType::Response),
            _ => Err(serde::de::Error::custom("invalid message type")),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Body {
    Test { test: String },
}
