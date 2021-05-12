use azure_core::prelude::Range;
use azure_core::HttpClient;
use azure_storage::blob::container::PublicAccess;
use azure_storage::blob::prelude::{AsBlobClient, AsContainerClient};
use azure_storage::clients::AsStorageClient;
use azure_storage::core::clients::{StorageAccountClient, StorageClient};
use reqwest;
use std::error::Error;
use std::sync::Arc;
use url::Url;

#[derive(Debug, Clone)]
pub struct BlobClient {
    client: Arc<StorageClient>,
}

impl BlobClient {
    pub fn new(account_name: impl Into<String>, account_key: impl Into<String>) -> Arc<Self> {
        let http_client: Arc<Box<dyn HttpClient>> = Arc::new(Box::new(reqwest::Client::new()));
        let storage_account_client =
            StorageAccountClient::new_access_key(http_client.clone(), account_name, account_key);

        Arc::new(Self {
            client: storage_account_client.as_storage_client(),
        })
    }

    // uses for unit tests only
    pub fn new_emulator(
        blob_storage_url_str: impl Into<String>,
        table_storage_url_str: impl Into<String>,
    ) -> Arc<Self> {
        let blob_storage_url = Url::parse(&blob_storage_url_str.into()).unwrap();
        let table_storage_url = Url::parse(&table_storage_url_str.into()).unwrap();

        let http_client: Arc<Box<dyn HttpClient>> = Arc::new(Box::new(reqwest::Client::new()));

        let storage_account_client =
            StorageAccountClient::new_emulator(http_client, &blob_storage_url, &table_storage_url);

        Arc::new(Self {
            client: storage_account_client.as_storage_client(),
        })
    }

    pub async fn create_container(
        &self,
        container_name: impl Into<String>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let container_client = self.client.as_container_client(container_name);

        let _res = container_client
            .create()
            .public_access(PublicAccess::None)
            .execute()
            .await?;

        Ok(())
    }

    pub async fn get(
        &self,
        container_name: impl Into<String>,
        blob_name: impl Into<String>,
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        let blob_client = self
            .client
            .as_container_client(container_name)
            .as_blob_client(blob_name);

        let response = blob_client
            .get()
            .range(Range::new(0, 128000))
            .execute()
            .await?;

        let s_content = String::from_utf8(response.data.to_vec())?;

        Ok(s_content)
    }
}
