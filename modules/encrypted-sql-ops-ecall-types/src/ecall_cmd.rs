/// Commands registered via [register_ecall!()](frame-enclave::register_ecall).
///
/// Has 1-to-1 relationship with SQL function calls.
/// TODO: introduce exit-less mechanism.
#[allow(missing_docs)]
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum EcallCmd {
    EncintegerFrom = 1,
    EncintegerAvgStateFunc = 2,
    EncintegerAvgFinalFunc = 3,
}
