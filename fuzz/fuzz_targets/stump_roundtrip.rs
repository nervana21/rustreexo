// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use rustreexo_fuzz::arbitrary_hashes;
use rustreexo_fuzz::stateful::call_one_of;
use rustreexo_fuzz::stateful::limited_while;
use rustreexo_fuzz::stateful::pick;
use rustreexo_fuzz::stateful::ObjectPool;
use rustreexo_fuzz::stump_add_only;
use rustreexo_fuzz::stump_roundtrip;
use rustreexo_fuzz::AccStump;
use rustreexo_fuzz::MAX_BATCH;
use rustreexo_fuzz::MAX_LEAVES;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let mut pool = ObjectPool::<AccStump>::new();

    limited_while(&mut u, 10_000, |u| {
        call_one_of(u, 3, |idx, u| match idx {
            0 => {
                let adds = arbitrary_hashes(u, MAX_BATCH.min(MAX_LEAVES));
                let stump = stump_add_only(AccStump::new(), &adds);
                stump_roundtrip(&stump);
                pool.push(stump);
            }
            1 => {
                if let Some(stump) = pick(u, pool.as_slice()) {
                    let room = MAX_LEAVES.saturating_sub(stump.leaves as usize);
                    let adds = if room == 0 {
                        Vec::new()
                    } else {
                        arbitrary_hashes(u, room.min(MAX_BATCH))
                    };
                    let grown = stump_add_only(stump.clone(), &adds);
                    stump_roundtrip(&grown);
                    pool.push(grown);
                }
            }
            2 => {
                if let Some(stump) = pick(u, pool.as_slice()) {
                    stump_roundtrip(stump);
                }
            }
            _ => {}
        });
    });
});
