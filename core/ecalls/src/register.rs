#[macro_export]
macro_rules! register_ecall {
    ( $( ($cmd: path, $input: ty, $output: ty), )* ) => {
        fn ecall_handler(cmd: u32, input: &[u8]) -> anyhow::Result<Vec<u8>> {
            match cmd {
                $(
                    $cmd => inner_ecall_handler::<$input, $output>(input),
                )*
                _ => anyhow::bail!("Not registered the ecall command"),
            }
        }

        fn inner_ecall_handler<I, O>(input: &[u8]) -> anyhow::Result<Vec<u8>>
        where
            I: codec::Decode,
            O: codec::Encode,
        {
            unimplemented!();
        }
    };

    #[no_mangle]
    pub extern "C" fn ecall_entry_point(
        command: u32,
        input_buf: *const u8,
        input_len: usize,
        output_buf: *mut u8,
        output_max_len: usize,
        output_len: &mut usize,
    ) -> anonify_types::EnclaveStatus {
        let input = unsafe { std::slice::from_raw_parts(input_buf, input_len) };
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

        if res_len > out_max {
            println!("Result buffer length is over output_max: output_max={}, res_len={}", out_max, res_len);
            return anonify_types::EnclaveStatus::error();
        }
        unsafe {
            std::prt::copy_nonoverlapping(res.as_ptr(), output_buf, res_len);
        }

        anonify_types::EnclaveStatus::success()
    }
}
