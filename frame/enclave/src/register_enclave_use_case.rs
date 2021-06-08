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
