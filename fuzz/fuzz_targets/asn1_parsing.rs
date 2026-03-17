#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test ASN.1 parsing with arbitrary input
    let _ = cer_viewer::formats::asn1::parse_asn1(data, 10);
});
