#[macro_export]
macro_rules! register_enclave_use_case {
    (   $ctx: expr,
        $(  $(#[$feature: meta])*
            $use_case: ty,
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
            use log::error;

            match cmd {
                $(
                    $(#[$feature])*
                    <$use_case>::ENCLAVE_USE_CASE_ID => <$use_case>::ecall_entry_point(
                        input_buf,
                        input_len,
                        output_buf,
                        ecall_max_size,
                        output_len,
                        $ctx
                    ).unwrap_or_else(|e| {
                        error!("Error in enclave (ecall_entry_point): {:?}", e);
                        frame_types::EnclaveStatus::error()
                    }),
                )*
                _ => unreachable!("Not registered the ecall command"),
            }
        }
    }
}
