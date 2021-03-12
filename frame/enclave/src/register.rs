#[macro_export]
macro_rules! register_ecall {
    (   $ctx: expr,
        $max_mem: expr,
        $runtime_exec: ty,
        $ctx_ops: ty,
        $( ($cmd: path, $handler: ty), )*
    ) => {
        use log::debug;
        use std::time;
        fn ecall_handler(cmd: u32, input: &mut [u8]) -> anyhow::Result<Vec<u8>> {
            match cmd {
                $(
                    $cmd => inner_ecall_handler::<$handler>(input),
                )*
                _ => anyhow::bail!("Not registered the ecall command"),
            }
        }

        fn inner_ecall_handler<EE>(input_payload: &[u8]) -> anyhow::Result<Vec<u8>>
        where
            EE: EnclaveEngine,
        {
            #[cfg(feature = "runtime_enabled")]
            let res = {
                let ciphertext = bincode::deserialize(&input_payload[..])
                    .map_err(|e| anyhow!("{:?}", e))?;

                let st4 = std::time::SystemTime::now();
                debug!("########## st4: {:?}", st4);
                let input = EE::decrypt::<$ctx_ops>(ciphertext, $ctx)?;
                EE::eval_policy(&input)?;

                let st5 = std::time::SystemTime::now();
                debug!("########## st5: {:?}", st5);
                EE::handle::<$runtime_exec, $ctx_ops>(input, $ctx, $max_mem)?
            };

            let st9 = std::time::SystemTime::now();
            debug!("########## st9: {:?}", st9);
            #[cfg(not(feature = "runtime_enabled"))]
            let res = EE::handle_without_runtime::<$ctx_ops>($ctx)?;

            bincode::serialize(&res).map_err(Into::into)
        }

        #[no_mangle]
        pub extern "C" fn ecall_entry_point(
            command: u32,
            input_buf: *mut u8,
            input_len: usize,
            output_buf: *mut u8,
            output_max_len: usize,
            output_len: &mut usize,
        ) -> frame_types::EnclaveStatus {
            let input = unsafe { std::slice::from_raw_parts_mut(input_buf, input_len) };
            let res = unsafe {
                match ecall_handler(command, input) {
                    Ok(out) => out,
                    Err(e) => {
                        println!("Error in enclave (ecall_entry_point): command: {:?}, error: {:?}", command, e);
                        return frame_types::EnclaveStatus::error();
                    }
                }
            };

            let res_len = res.len();
            *output_len = res_len;

            if res_len > output_max_len {
                println!("Result buffer length is over output_max: output_max={}, res_len={}", output_max_len, res_len);
                return frame_types::EnclaveStatus::error();
            }
            unsafe {
                ptr::copy_nonoverlapping(res.as_ptr(), output_buf, res_len);
            }

            frame_types::EnclaveStatus::success()
        }
    }
}
