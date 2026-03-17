#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test CRL parsing with arbitrary input
    let _ = cer_viewer::validation::crl::CertificateRevocationList::from_der(data);
});
