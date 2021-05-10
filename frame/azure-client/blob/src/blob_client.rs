use azure_core::prelude::Range;
use azure_core::HttpClient;
use azure_storage::blob::prelude::{AsBlobClient, AsContainerClient, BlobClient};
use azure_storage::clients::AsStorageClient;
use azure_storage::core::clients::StorageAccountClient;
use reqwest;
use std::error::Error;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Client {
    client: Arc<BlobClient>,
}

impl Client {
    pub fn new(account_name: String, key: String, container_name: String) -> Arc<Self> {
        Arc::new(Self {
            account_name,
            key,
            container_name,
        })
    }
}
