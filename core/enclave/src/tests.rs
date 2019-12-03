use super::*;
use attestation::*;

pub(crate) fn test_get_report() {
    let service = AttestationService::new(DEV_HOSTNAME, REPORT_PATH, IAS_DEFAULT_RETRIES);
    // let report = service.get_report(quote: &str, ias_api_key: &str)
}
