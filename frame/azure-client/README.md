# frame::azure-client
The frame::azure-client is wrapper library of azure sdk.

- [azure-sdk-for-rust](https://github.com/Azure/azure-sdk-for-rust)

## Features
- Blob Client
  - gets a blob
  - puts a blob
  - gets list of container names
  - creates a container
  
## Usage
Puts a blob data
```rust
// Creates the azure client instance.
let client = azure_client::blob::BlobClient::new("account", "key");
// Puts a blob data
let data = "testdata";
let _res = client
    .put("emulcont", "test.txt", data.as_bytes())
    .await
    .unwrap();
```

Gets a blob data
```rust
// Creates the azure client instance.
let client = azure_client::blob::BlobClient::new("account", "key");
// Puts a blob data
let data = "testdata";
let res = client.get("emulcont", "test.txt").await.unwrap();
```
  
## Run unit tests
Local unit tests run on Azurite.
- [Azurite](https://github.com/Azure/Azurite)

```
$ docker compose run -d
$ cargo test -- --nocapture
```
