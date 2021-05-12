#[tokio::test]
async fn test_get() {
    let client = azure_client::blob::BlobClient::new_emulator(
        "http://127.0.0.1:10000",
        "http://127.0.0.1:10002",
    );
    let _res = client
        .create_container("devstoreaccount1/emulcont")
        .await
        .unwrap();
}
