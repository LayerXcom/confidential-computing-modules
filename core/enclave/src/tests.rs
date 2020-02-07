use super::*;
use attestation::*;
use context::EnclaveContext;
use anonify_common::kvs::MemoryDB;

pub(crate) fn test_get_report() {
    let service = AttestationService::new(DEV_HOSTNAME, REPORT_PATH);
    let quote = EnclaveContext::<MemoryDB>::new(TEST_SPID).unwrap().get_quote().unwrap();
    println!("quote: {}", quote);
    let (report, sig) = service.get_report_and_sig(&quote, TEST_SUB_KEY).unwrap();
    // println!("report: {}", report);
    // println!("report: {}", sig);
}
