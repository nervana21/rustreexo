// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use rustreexo_fuzz::build_proof;
use rustreexo_fuzz::proof_roundtrip;
use rustreexo_fuzz::stateful::call_one_of;
use rustreexo_fuzz::stateful::limited_while;
use rustreexo_fuzz::stateful::pick;
use rustreexo_fuzz::stateful::ObjectPool;
use rustreexo_fuzz::AccProof;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let mut pool = ObjectPool::<AccProof>::new();

    limited_while(&mut u, 10_000, |u| {
        call_one_of(u, 2, |idx, u| match idx {
            0 => {
                let proof = build_proof(u);
                proof_roundtrip(&proof);
                pool.push(proof);
            }
            1 => {
                if let Some(proof) = pick(u, pool.as_slice()) {
                    proof_roundtrip(proof);
                }
            }
            _ => {}
        });
    });
});
