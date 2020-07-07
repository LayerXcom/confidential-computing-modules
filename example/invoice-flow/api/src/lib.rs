use std::fmt;
use serde::{Deserialize, Serialize};

pub mod deploy {
    pub mod post {
        use super::super::*;

        #[derive(Debug, Clone, Eq, PartialEq, Hash, Default, Deserialize, Serialize)]
        pub struct Response(pub String);
    }
}

pub mod notification {
    pub mod post {
        use super::super::*;

        #[derive(Clone, Deserialize, Serialize)]
        pub struct Request {
            pub keyfile_index: usize,
        }

        impl Request {
            pub fn new(
                keyfile_index: usize,
            ) -> Self {
                Request{ keyfile_index }
            }
        }

        impl fmt::Debug for Request {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    f,
                    "Request {{ keyfile_index: {:?} }}",
                    &self.keyfile_index
                )
            }
        }
    }
}

pub mod contract_addr {
    pub mod post {
        use super::super::*;

        #[derive(Clone, Deserialize, Serialize, Debug)]
        pub struct Request {
            pub contract_addr: String,
        }

        impl Request {
            pub fn new(contract_addr: String) -> Self {
                Request { contract_addr }
            }
        }
    }
}
