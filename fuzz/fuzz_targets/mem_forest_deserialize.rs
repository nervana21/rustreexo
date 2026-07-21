// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use rustreexo_fuzz::clamp_wire;
use rustreexo_fuzz::stateful::call_one_of;
use rustreexo_fuzz::stateful::consume_bytes;
use rustreexo_fuzz::stateful::limited_while;
use rustreexo_fuzz::stateful::pick_index;
use rustreexo_fuzz::stateful::InputPool;
use rustreexo_fuzz::stateful::ObjectPool;
use rustreexo_fuzz::AccMemForest;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let mut raw = InputPool::new();
    let mut forests = ObjectPool::<AccMemForest>::new();

    limited_while(&mut u, 10_000, |u| {
        call_one_of(u, 2, |idx, u| match idx {
            0 => {
                let Some(bytes) = consume_bytes(u) else {
                    return;
                };
                let bytes = clamp_wire(bytes);
                if let Ok(forest) = AccMemForest::deserialize(bytes) {
                    forests.push(forest);
                }
                raw.push(bytes.to_vec());
            }
            1 => {
                let Some(i) = pick_index(u, raw.len()) else {
                    return;
                };
                let bytes = raw.get(i).expect("pooled");
                if let Ok(forest) = AccMemForest::deserialize(bytes) {
                    forests.push(forest);
                }
            }
            _ => {}
        });
    });
});
