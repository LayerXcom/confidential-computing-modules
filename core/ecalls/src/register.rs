#[macro_export]
macro_rules! register_ecall {
    () => {

    };

    // #[no_mangle]
    // pub unsafe extern "C" fn ecall_entry_point(
    //     command: u32,
    //     input_buf: *const u8,
    //     input_len: usize,
    //     output_buf: *mut u8,
    //     output_max_len: usize,
    //     output_len: &mut usize,
    // ) -> anonify_types::EnclaveStatus {
    //     let input = unsafe { std::slice::from_raw_parts(input_buf, input_len) };
    //     unimplemented!();
    // }
}
