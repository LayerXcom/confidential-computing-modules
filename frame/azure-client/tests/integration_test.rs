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

        // emulcontコンテナが存在することを確認する
        let res = client.list_containers().await.unwrap();
        assert_eq!(vec!("emulcont"), res);

        // blobにデータをputする
        let data = "bbbbb";
        let _res = client
            .put("emulcont", "test.txt", data.as_bytes())
            .await
            .unwrap();

        // putしたデータを取得できることを確認する
        let res = client.get("emulcont", "test.txt").await.unwrap();
        assert_eq!(data, res);
    }
}
