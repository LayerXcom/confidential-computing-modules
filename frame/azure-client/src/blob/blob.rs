use azure_core::prelude::Range;
use azure_core::HttpClient;
use azure_storage::blob::container::PublicAccess;
use azure_storage::blob::prelude::{AsBlobClient, AsContainerClient};
use azure_storage::clients::AsStorageClient;
use azure_storage::core::clients::{StorageAccountClient, StorageClient};
use bytes::Bytes;
use reqwest;
use std::error::Error;
use std::num::NonZeroU32;
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

    // uses for Azurite.
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

    pub async fn list_containers(&self) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
        let max_results = NonZeroU32::new(1024).unwrap();
        let iv = self
            .client
            .list_containers()
            .max_results(max_results)
            .execute()
            .await?;

        let mut vector: Vec<String> = Vec::with_capacity(iv.incomplete_vector.len());
        for cont in iv.incomplete_vector.iter() {
            vector.push(cont.name.clone());
        }

        Ok(vector)
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

    pub async fn put(
        &self,
        container_name: impl Into<String>,
        blob_name: impl Into<String>,
        data: impl Into<Bytes>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let blob_client = self
            .client
            .as_container_client(container_name)
            .as_blob_client(blob_name);

        let _res = blob_client
            .put_block_blob(data)
            .content_type("text/plain")
            .execute()
            .await?;

        Ok(())
    }
}
