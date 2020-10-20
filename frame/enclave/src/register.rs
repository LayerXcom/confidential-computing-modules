#[macro_export]
macro_rules! register_ecall {
    (   $ctx: expr,
        $max_mem: expr,
        $runtime_exec: ty,
        $ctx_ops: ty,
        $( ($cmd: path, $handler: ty), )*
    ) => {
        fn ecall_handler(cmd: u32, input: &mut [u8]) -> anyhow::Result<Vec<u8>> {
            match cmd {
                $(
                    $cmd => inner_ecall_handler::<$handler>(input),
                )*
                _ => anyhow::bail!("Not registered the ecall command"),
            }
        }

        fn inner_ecall_handler<EE>(input_payload: &mut [u8]) -> anyhow::Result<Vec<u8>>
        where
            EE: EnclaveEngine,
            EE::EI: EcallInput + codec::Decode,
            EE::EO: EcallOutput + codec::Encode,
        {
            let input = EE::EI::decode(&mut &input_payload[..])
                .map_err(|e| anyhow!("{:?}", e))?;
            EE::eval_policy(&input)?;
            let res = EE::handle::<$runtime_exec, $ctx_ops>(input, $ctx, $max_mem)?;

            Ok(res.encode())
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
