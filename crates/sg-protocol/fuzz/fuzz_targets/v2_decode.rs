#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use sg_protocol::v2::{PayloadLimit, V2Envelope};

fuzz_target!(|data: &[u8]| {
    let _ = V2Envelope::decode(Bytes::copy_from_slice(data), PayloadLimit::new(data.len()));
});
