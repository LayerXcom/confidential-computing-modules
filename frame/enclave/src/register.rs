#[macro_export]
macro_rules! register_ecall {
    (   $ctx: expr,
        $max_mem: expr,
        $runtime_exec: ty,
        $ctx_ops: ty,
        $( ($cmd: path, $input: ty, $output: ty), )*
    ) => {
        fn ecall_handler(cmd: u32, input: &mut [u8]) -> anyhow::Result<Vec<u8>> {
            match cmd {
                $(
                    $cmd => inner_ecall_handler::<$input, $output>(input),
                )*
                _ => anyhow::bail!("Not registered the ecall command"),
            }
        }

        fn inner_ecall_handler<I, O>(input_payload: &mut [u8]) -> anyhow::Result<Vec<u8>>
        where
            I: Into<II> + EcallInput + codec::Decode,
            II: EcallHandler + codec::Decode,
            O: EcallOutput + codec::Encode,
        {
            let input = II::decode(&mut &input_payload[..])
                .map_err(|e| anyhow!("{:?}", e))?;
            let res = input.handle::<$runtime_exec, $ctx_ops>($ctx, $max_mem)?;

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
        ) -> anonify_types::EnclaveStatus {
            let input = unsafe { std::slice::from_raw_parts_mut(input_buf, input_len) };
            let res = unsafe {
                match ecall_handler(command, input) {
                    Ok(out) => out,
                    Err(e) => {
                        println!("Error (ecall_entry_point): command: {:?}, error: {:?}", command, e);
                        return anonify_types::EnclaveStatus::error();
                    }
                }
            };

            let res_len = res.len();
            *output_len = res_len;

            if res_len > output_max_len {
                println!("Result buffer length is over output_max: output_max={}, res_len={}", output_max_len, res_len);
                return anonify_types::EnclaveStatus::error();
            }
            unsafe {
                ptr::copy_nonoverlapping(res.as_ptr(), output_buf, res_len);
            }

            anonify_types::EnclaveStatus::success()
        }
    }
}
