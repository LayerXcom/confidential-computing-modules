# ディレクトリ構造

* enclave上のコードとenclave外(host)のコードを互いにimportして使うことはできません。`features`でビルド時・インポート時に場合分けすることでenclave/host共通のコードベースを使っているファイルもあります。

frame --> modules --> example の依存関係があります。

* frame: ecall/ocallの抽象化、modulesで共通的に用いるプリミティブ実装などのレイヤ
* modules:　frameのライブラリを用いて、TEEノードのコアロジックの実装をするレイヤ
* example: クライアント、サーバー、状態遷移などアプリケーション部分の実装をするレイヤ

```
.
├── config: ファイルパス・
├── contracts: スマートコントラクト
├── docker
├── edl: ecall/ocallのインターフェース定義ディレクトリ
│   ├── Anonify_common.edl:
│   └── Anonify_test.edl: テスト用のEDLファイル
├── example
│   ├── erc20
│   │   ├── cli: (host)　デモ・動作確認用クライアント
│   │   ├── enclave: (enclave) ecall関数の定義、状態遷移ロジックの記述
│   │   └── server: (host) REST APIエンドポイント定義サーバー (bin)
│   └── wallet: （デモ・動作確認用）CLIで用いる署名秘密鍵の管理
├── frame:
│   ├── common: (enclave/host) 共通的に使われる暗号プリミティブ系など
│   ├── config: (enclave/host) 共通的に使われる環境変数による定義など
│   ├── enclave: (enclave) ecallロジックを簡単に記述できるようマクロ
│   ├── host: (host) enclaveの初期化、ocallロジック実装など
│   ├── mra-tls: (enclave) 鍵バックアップ時、異なるマシン上のTEEとmutual attested TLS
│   ├── remote-attestation: (enclave) リモートアテステーションの実装
│   ├── retrier: (host/enclave) リクエスト送信時のリトライ処理
│   ├── runtime: (enclave/host): modulesや状態遷移ロジック定義で使うマクロ実装
│   ├── sodium: (enclave/host): Sodiumライブラリのラッパー実装
│   ├── treekem: (enclave/host) TEEノードのグループ鍵実装
│   └── types: (enclave/host) EDLで使う型定義
├── modules:
│   ├── anonify-enclave: (enclave) anonifyのenclave内ロジックの実装
│   ├── anonify-eth-driver: (host) Etheream系ブロックチェーンとweb3経由でやりとり
│   ├── anonify-ecall-types: (enclave/host) anonifyモジュールのenclave<->host間でやりとりする型定義
│   ├── key-vault-enclave: (enclave) 鍵バックアップEnclaveのロジック
│   ├── key-vault-host: (host)
│   └── key-vault-ecall-types: (enclave/host) key-vaultモジュールのenclave<->host間でやりとりする型定義
├── nodes:
│   ├── state-runtime
│   │   ├── api: (host) リクエスト・レスポンス型の定義
│   │   └── server: (host) APIサーバーのハンドラ実装 (lib)
│   └── key-vault
│       ├── enclave: (enclave) ecall関数の定義
│       └── server: (host) REST APIエンドポイント定義サーバー (bin)
├── scripts
└── tests: 結合テスト・Enclave内のユニットテストなど
```
