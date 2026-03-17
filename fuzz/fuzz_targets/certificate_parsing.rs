#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test certificate parsing with arbitrary input
    let _ = cer_viewer::cert::parse_certificate(data);
});
