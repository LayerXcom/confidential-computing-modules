/// Commands registered via [register_ecall!()](frame-enclave::register_ecall).
///
/// Has 1-to-1 relationship with SQL function calls.
/// TODO: introduce exit-less mechanism.
#[allow(missing_docs)]
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum Cmd {
    ENCINTEGER_FROM = 1,
    ENCINTEGER_AVG_STATE_FUNC = 2,
    ENCINTEGER_AVG_FINAL_FUNC = 3,
}
