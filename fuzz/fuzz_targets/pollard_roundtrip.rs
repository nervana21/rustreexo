// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use rustreexo_fuzz::arbitrary_hashes;
use rustreexo_fuzz::pollard_add_remember_all;
use rustreexo_fuzz::pollard_roundtrip;
use rustreexo_fuzz::stateful::call_one_of;
use rustreexo_fuzz::stateful::limited_while;
use rustreexo_fuzz::stateful::pick;
use rustreexo_fuzz::stateful::ObjectPool;
use rustreexo_fuzz::AccPollard;
use rustreexo_fuzz::MAX_BATCH;
use rustreexo_fuzz::MAX_LEAVES;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let mut pool = ObjectPool::<AccPollard>::new();

    limited_while(&mut u, 10_000, |u| {
        call_one_of(u, 3, |idx, u| match idx {
            0 => {
                let adds = arbitrary_hashes(u, MAX_BATCH.min(MAX_LEAVES));
                let mut pollard = AccPollard::new();
                pollard_add_remember_all(&mut pollard, &adds);
                pollard_roundtrip(&pollard);
                pool.push(pollard);
            }
            1 => {
                if let Some(base) = pick(u, pool.as_slice()) {
                    let mut pollard = base.clone();
                    let room = MAX_LEAVES.saturating_sub(pollard.leaves() as usize);
                    let adds = if room == 0 {
                        Vec::new()
                    } else {
                        arbitrary_hashes(u, room.min(MAX_BATCH))
                    };
                    pollard_add_remember_all(&mut pollard, &adds);
                    pollard_roundtrip(&pollard);
                    pool.push(pollard);
                }
            }
            2 => {
                if let Some(pollard) = pick(u, pool.as_slice()) {
                    pollard_roundtrip(pollard);
                }
            }
            _ => {}
        });
    });
});
