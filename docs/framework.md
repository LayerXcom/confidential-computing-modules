# `frame/` の詳説

`frame/` は、ecall/ocall を抽象化したフレームワークです。
以後このドキュメントで「フレームワーク」は `frame/` 以下の諸々を指します。

本リポジトリを読んだり修正していく上でフレームワークへの理解は重要です。
このドキュメントの目的は以下の通りです:

- 抽象化対象の概念が整理できる
- 実際にフレームワークを用いて `modules/` を書けるようになる

## 前提

- SGXに関する座学知識は前提として必要です。
- SGXSDKに関する知識は不要です。

## 概念整理: Enclave, Host

フレームワークの中では、 **Enclave** の外の世界を **Host** と呼称します。
**Ecall** によって Host から Enclave に処理が移り、 **Ocall** （など）によって Enclave から Host に処理が移ります。

```text
  [Host instruction/data memory]  |  [Enclave instruction/data memory]
                                  |
                        ecall  ------>
                               <------ ocall
                                  |
                                  |
```

## ecall の実現方法

フレームワークを使って Enclave 内の処理を書く方法は後述しますが、Enclave 内の処理があったとして、それを呼び出すためにはどのように ecall を定義してあげれば良いでしょうか。

本リポジトリの .edl ファイルには `ecall_entry_point()` という唯一の encall 関数が宣言されています。
`ecall_entry_point()` は Enclave 処理の種類を示す `cmd: u32` や処理の入出力を引数として取る汎用的な関数で、この関数1つだけで任意の Enclave 処理へのディスパッチャとして働きます（少々古い例えですが、SOAP 的なプロトコルですね）。

各アプリケーション（典型的には `example/**/enclave`）で `ecall_entry_point()` 関数の実装を書くことになりますが、マクロが代替してくれます（詳細後述）。

`ecall_entry_point()` 関数呼び出しはフレームワークにより隠蔽されているため、普段意識するのは「Host側からEnclave側に処理を移す際に経由する `EcallController`」や「Enclave 側処理のエントリポイントである `EnclaveUseCase`」です。

## ocall の実現方法

TBD

## Host ~ Enclave の実装方法をボトムアップに

以降、フレームワークの使い方を Enclave 処理 -> Host 側の main 関数の順序でボトムアップに解説します。

### Enclave 処理の実装方法

`trait BasicEnclaveUseCase` を impl するのが基本です。
（Enclave 内でのステートマシン利用に特化した `trait StateRuntimeEnclaveUseCase` もあります。）

以下に概略的なコードを示します。
（本ドキュメントで出てくるコードは理解を促す目的であり、コンパイルが通ることは期待してはいけません。フレームワーク側に完全に追従できているとも限らないので...）

```rust
impl<'c, C> BasicEnclaveUseCase<'c, C> for MyEnclaveUseCase
where
    C: ConfigGetter,
{
    type EI = MyEnclaveInput;
    type EO = MyEnclaveOutput;

    const ENCLAVE_USE_CASE_ID: u32 = MY_ENCLAVE_USE_CASE_ID;

    fn new(enclave_input: Self::EI, enclave_context: &'c C) -> Result<Self> {
        ...
    }

    fn run(self) -> Result<Self::EO> {
        ...
    }
}
```

`fn new()` に Enclave Input が渡されるので、必要に応じて変換処理などをした後で `MyEnclaveUseCase` のフィールドとして持たせましょう。`enclave_context` は Enclave に関する設定値が入るので、これも必要に応じて `MyEnclaveUseCase` のフィールドとして持たせます。
そして `fn run()` の中に、Enclave内で行いたい処理を記述します。

```rust
    const ENCLAVE_USE_CASE_ID: u32 = MY_ENCLAVE_USE_CASE_ID;
```

の箇所は次のコントローラーのセクションで解説します。

### Enclave 処理を呼び出すコントローラーの実装方法

`trait EcallController` を impl します。
お気づきの人はお気づきかと思いますが、 Controller, UseCase の名称は Clean Architecture から来ています。

```rust
impl EcallController for MyEcallController {
    type HI = MyHostInput;
    type EI = MyEnclaveInput;
    type EO = MyEnclaveOutput;
    type HO = MyHostOutput;

    const ENCLAVE_USE_CASE_ID: u32 = MY_ENCLAVE_USE_CASE_ID;
    const EI_MAX_SIZE: usize = 1024;

    fn translate_input(host_input: Self::HI) -> Result<Self::EI> { ... }

    fn translate_output(enclave_output: Self::EO) -> Result<Self::HO> { ... }
}
```

関連型が4つもあって面食らいますが、以下のようなデータフローです。

```text
  [Host instruction/data memory]  |  [Enclave instruction/data memory]
                                  |
          HI (Host Input) ---- <ecall>  ---> EI (Enclave Input)
                                  |                  |
                                  |           <EnclaveUseCase>
                                  |                  |
                                  |                  v
      HO (Host Output) <--- <ecall return> --- EO (Enclave Output)
                                  |
```

上図からは読み取れませんが、実際には `Host Input -> Enclave Input` の変換と `Enclave Output -> Host Output` の変換は Host のメモリ空間で行われます。
例えばHost側では暗号文で、Enclave内では平文でデータ処理を行うようなアプリケーションを開発するならば、Enclave Input/Output までは暗号文で扱い、Enclave内で更に追加で平文のデータ構造を持つようにしましょう。

```rust
    const ENCLAVE_USE_CASE_ID: u32 = MY_ENCLAVE_USE_CASE_ID;
```

の部分は、コントローラーが呼び出すべきユースケースを指定しています。
EnclaveUseCase 側の定義にも全く同じ const 定義があったのを覚えているでしょうか？（忘れていたら前のセクションに戻ってください）

.edl で定義されている唯一のecall関数 `ecall_entry_point()` は、 `cmd: u32` という引数によって Enclave 処理をディスパッチしています。コントローラーとユースケースの紐付けがこの `u32` によって行われているというわけです。
（通常は `impl<U: UseCase> Controller<U> for MyController {}` のように型パラメータで紐付けることが自然ですが、Cのプリミティブ変数でディスパッチを表現することが必要なのでこうなっています。）

```rust
    const EI_MAX_SIZE: usize = 1024;
```

の部分は、Enclave Input の許容できる最大サイズを指定してください。
Enclave Input が固定長フィールドのみから構成される場合はシンプルですが、可変長の Enclave Input を使う場合は「通常のユースケースにおける最大」を指定しましょう。
この定数の目的は、不正な入力値によるDoS攻撃を避けるためです。

### `ecall_entry_point()` からユースケースがディスパッチされるようにする

コントローラーを呼び出した際、ユースケースに処理を流すためには、（ユースケースはEnclaveで走るので）ecall が必要です。
本リポジトリ唯一の ecall である `ecall_entry_point()` を定義しつつ、その定義の中身が「各ユースケースへの処理のディスパッチ」になるようにしたいところですが、 `register_enclave_use_case!()` マクロがやってくれます。

```rust
register_enclave_use_case!(
    MyEnclaveUseCase,
    MyEnclaveUseCase2,
);
```

このマクロによって、大まかに言って下記のコードが生成されます。

```rust
#[no_mangle]
pub extern "C" fn ecall_entry_point(
    cmd: u32,
    input_buf: *mut u8,
    input_len: usize,
    output_buf: *mut u8,
    ecall_max_size: usize,
    output_len: &mut usize,
) -> frame_types::EnclaveStatus {
    let input = ...;
    let output = match cmd {
        MyEnclaveUseCase::ENCLAVE_USE_CASE_ID => MyEnclaveUseCase::run(input),
        MyEnclaveUseCase2::ENCLAVE_USE_CASE_ID => MyEnclaveUseCase2::run(input),
    };
    ...
}
```

コントローラーを呼び出すと、内部的に `ecall_entry_point(MyEcallController::ENCLAVE_USE_CASE_ID, ...)` が呼び出されます。
IDの一致により `MyEcallController` -> `MyEnclaveUseCase` の呼び出しが実現されてますね。

### コントローラーの呼び出し

あとは Host 側でコントローラーを呼び出せば Enclave 処理の実現が完了です。

```rust
fn main() {
    ...

    let enclave = EnclaveDir::new()
        .init_enclave(is_debug)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();

    let my_host_output = MyEcallController::run(my_host_input, eid).unwrap();

    ...
}
```
