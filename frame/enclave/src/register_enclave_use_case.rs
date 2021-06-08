#[macro_export]
macro_rules! register_enclave_use_case {
    (   $ctx: expr,
        $max_mem: expr,
        $runtime_exec: ty,
        $ctx_ops: ty,
        $(  $(#[$feature: meta])*
            ($cmd: path, $use_case: ty),
        )*
    ) => {
        #[cfg(feature = "runtime_enabled")]
        fn ecall_handler(cmd: u32, input: &mut [u8], ecall_max_size: usize) -> anyhow::Result<Vec<u8>> {
            match cmd {
                $(
                    $(#[$feature])*
                    $cmd => inner_ecall_handler::<$use_case>(input, ecall_max_size),  // TODO ここでマクロで定義した関数呼び出しではなく、EnclaveUseCaseのデフォルト関数呼び出しにする（マクロを小さくする）
                )*
                _ => anyhow::bail!("Not registered the ecall command"),
            }
        }

        #[cfg(feature = "runtime_enabled")]
        fn inner_ecall_handler<EE>(input_payload: &[u8], ecall_max_size: usize) -> anyhow::Result<Vec<u8>>
        where
            EE: StateRuntimeEnclaveUseCase,
        {
            let res = {
                let enclave_input = bincode::DefaultOptions::new()
                    .with_limit(ecall_max_size as u64)
                    .deserialize(&input_payload[..])
                    .map_err(|e| anyhow!("{:?}", e))?;

                let slf = EE::new::<$ctx_ops>(enclave_input, $ctx)?;
                EE::eval_policy(&slf)?;
                EE::run::<$runtime_exec, $ctx_ops>(slf, $ctx, $max_mem)?
            };

            bincode::serialize(&res).map_err(Into::into)
        }

        #[no_mangle]
        pub extern "C" fn ecall_entry_point(
            cmd: u32,
            input_buf: *mut u8,
            input_len: usize,
            output_buf: *mut u8,
            ecall_max_size: usize,
            output_len: &mut usize,
        ) -> frame_types::EnclaveStatus {
            match cmd {
                $(
                    $(#[$feature])*
                    $cmd => <$use_case>::ecall_entry_point(input_buf,input_len,output_buf,ecall_max_size,output_len, $ctx),
                )*
                _ => unreachable!("Not registered the ecall command"),
            }
        }
    }
}
