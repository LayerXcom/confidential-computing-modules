#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_blob() {
        let client = azure_client::blob::BlobClient::new_emulator(
            "http://127.0.0.1:10000",
            "http://127.0.0.1:10002",
        );
        // コンテナがなければ作成する失敗しても無視
        let _res = client.create_container("devstoreaccount1/emulcont").await;

        let res = client.list_containers().await.unwrap();

        println!("{:?}", res);

        let data = "aaaaa";
        let _res = client
            .put("emulcont", "test.txt", data.as_bytes())
            .await
            .unwrap();

        let res = client.list_blobs("emulcont").await.unwrap();

        println!("{:?}", res);

        let res = client.get("emulcont", "test.txt").await.unwrap();

        println!("{}", res);
    }
}
