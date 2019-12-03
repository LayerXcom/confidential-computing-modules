use super::*;
use attestation::*;
use quote::EnclaveContext;

pub(crate) fn test_get_report() {
    let service = AttestationService::new(DEV_HOSTNAME, REPORT_PATH, IAS_DEFAULT_RETRIES);
    let quote = EnclaveContext::new("2C149BFC94A61D306A96211AED155BE9").unwrap().get_quote().unwrap();
    println!("quote: {}", quote);
    let report = service.get_report(&quote, "77e2533de0624df28dc3be3a5b9e50d9").unwrap();
    println!("report: {}", report);

}
