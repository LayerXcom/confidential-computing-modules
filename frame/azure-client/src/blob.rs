use anyhow::anyhow;
use azure_core::prelude::Range;
use azure_core::HttpClient;
use azure_storage::blob::container::PublicAccess;
use azure_storage::blob::prelude::{AsBlobClient, AsContainerClient};
use azure_storage::clients::AsStorageClient;
use azure_storage::core::clients::{StorageAccountClient, StorageClient};
use bytes::Bytes;
use std::sync::Arc;
#[cfg(test)]
use url::Url;

/// BlobClient is to access the Azure Storage APIs
#[derive(Debug, Clone)]
pub struct BlobClient {
    client: Arc<StorageClient>,
}

impl BlobClient {
    /// new instantiates a BlobClient object.
    pub fn new(account_name: impl Into<String>, account_key: impl Into<String>) -> Arc<Self> {
        let http_client: Arc<Box<dyn HttpClient>> = Arc::new(Box::new(reqwest::Client::new()));
        let storage_account_client =
            StorageAccountClient::new_access_key(http_client, account_name, account_key);

        Arc::new(Self {
            client: storage_account_client.as_storage_client(),
        })
    }

    /// new_emulator instantiates a BlobClient object that is for use Azurite only.
    #[cfg(test)]
    pub fn new_emulator(
        blob_storage_url_str: impl Into<String>,
        table_storage_url_str: impl Into<String>,
    ) -> Arc<Self> {
        // Panic occurs if URL parsing fails
        let blob_storage_url = Url::parse(&blob_storage_url_str.into()).unwrap();
        let table_storage_url = Url::parse(&table_storage_url_str.into()).unwrap();

        let http_client: Arc<Box<dyn HttpClient>> = Arc::new(Box::new(reqwest::Client::new()));

        let storage_account_client =
            StorageAccountClient::new_emulator(http_client, &blob_storage_url, &table_storage_url);

        Arc::new(Self {
            client: storage_account_client.as_storage_client(),
        })
    }

    /// get gets a blob data.
    pub async fn get(
        &self,
        container_name: impl Into<String>,
        blob_name: impl Into<String>,
    ) -> anyhow::Result<String> {
        let blob_client = self
            .client
            .as_container_client(container_name)
            .as_blob_client(blob_name);

        let response = blob_client
            .get()
            .range(Range::new(0, 2048)) // TODO: Fix range nums
            .execute()
            .await
            .map_err(|err| anyhow!(err))?;

        let s_content = String::from_utf8(response.data.to_vec())?;

        Ok(s_content)
    }

    /// put puts a blob data.
    pub async fn put(
        &self,
        container_name: impl Into<String>,
        blob_name: impl Into<String>,
        data: impl Into<Bytes>,
    ) -> anyhow::Result<()> {
        let blob_client = self
            .client
            .as_container_client(container_name)
            .as_blob_client(blob_name);

        let _res = blob_client
            .put_block_blob(data)
            .content_type("text/plain")
            .execute()
            .await
            .map_err(|err| anyhow!(err))?;

        Ok(())
    }

    // list up blob names
    pub async fn list(&self, container_name: impl Into<String>) -> anyhow::Result<Vec<String>> {
        let container_client = self.client.as_container_client(container_name);

        let blobs = container_client
            .list_blobs()
            .execute()
            .await
            .map_err(|err| anyhow!(err))?;

        let res = blobs
            .blobs
            .blobs
            .into_iter()
            .map(|blob| blob.name)
            .collect::<Vec<_>>();

        Ok(res)
    }

    /// list_containers gets list of container names.
    #[cfg(test)]
    pub async fn list_containers(&self) -> anyhow::Result<Vec<String>> {
        let iv = self
            .client
            .list_containers()
            .execute()
            .await
            .map_err(|err| anyhow!(err))?;

        let mut vector: Vec<String> = Vec::with_capacity(iv.incomplete_vector.len());
        for cont in iv.incomplete_vector.iter() {
            vector.push(cont.name.clone());
        }

        Ok(vector)
    }

    /// create_container creates a container.
    pub async fn create_container(&self, container_name: impl Into<String>) -> anyhow::Result<()> {
        let container_client = self.client.as_container_client(container_name);

        let _res = container_client
            .create()
            .public_access(PublicAccess::None)
            .execute()
            .await
            .map_err(|err| anyhow!(err))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::BlobClient;

    #[tokio::test]
    async fn test_blob() {
        env_logger::init();

        let ip = std::env::var("AZURITE_IP_ADDRESS").unwrap_or_else(|_| "127.0.0.1".to_string());

        let client = BlobClient::new_emulator(
            format!("http://{}:10000", ip),
            format!("http://{}:10002", ip),
        );

        // コンテナがなければ作成する失敗しても無視
        let _res = client.create_container("devstoreaccount1/emulcont").await;

        // emulcontコンテナが存在することを確認する
        let res = client.list_containers().await.unwrap();
        assert_eq!(vec!("emulcont"), res);

        // blobにデータをputする
        let data = "testdatatestdata";
        let _res = client
            .put("emulcont", "test.txt", data.as_bytes())
            .await
            .unwrap();

        // putしたデータを取得できることを確認する
        let res = client.get("emulcont", "test.txt").await.unwrap();
        assert_eq!(data, res);
    }
}
