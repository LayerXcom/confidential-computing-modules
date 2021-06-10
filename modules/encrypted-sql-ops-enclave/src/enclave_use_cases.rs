//! Use cases executed in enclave.

mod enc_integer_avg_final_func_use_case;
mod enc_integer_avg_state_func_use_case;
mod enc_integer_from_use_case;

pub use enc_integer_avg_final_func_use_case::EncIntegerAvgFinalFuncUseCase;
pub use enc_integer_avg_state_func_use_case::EncIntegerAvgStateFuncUseCase;
pub use enc_integer_from_use_case::EncIntegerFromUseCase;
