// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use rustreexo_fuzz::hash_from_seed;
use rustreexo_fuzz::stateful::call_one_of;
use rustreexo_fuzz::stateful::limited_while;
use rustreexo_fuzz::stateful::pick_index;
use rustreexo_fuzz::AccHash;
use rustreexo_fuzz::AccMemForest;
use rustreexo_fuzz::MAX_BATCH;
use rustreexo_fuzz::MAX_LEAVES;

struct Session {
    forest: AccMemForest,
    /// Currently present leaf hashes (for prove/delete).
    leaves: Vec<AccHash>,
    /// Total successful additions; matches [`MemForest::leaves`] (ever-added).
    added: u64,
}

impl Session {
    fn new() -> Self {
        Self {
            forest: AccMemForest::new(),
            leaves: Vec::new(),
            added: 0,
        }
    }

    fn add(&mut self, u: &mut Unstructured<'_>) {
        if self.leaves.len() >= MAX_LEAVES {
            return;
        }
        let room = MAX_LEAVES - self.leaves.len();
        let n = u.int_in_range(1..=room.min(MAX_BATCH).max(1)).unwrap_or(1);
        let mut adds = Vec::with_capacity(n);
        for _ in 0..n {
            let seed = u.arbitrary::<u8>().unwrap_or(0);
            adds.push(hash_from_seed(
                seed.wrapping_add(self.leaves.len() as u8).max(1),
            ));
        }
        if self.forest.modify(&adds, &[]).is_ok() {
            self.added += adds.len() as u64;
            self.leaves.extend(adds);
            // MemForest::leaves is ever-added, not live count.
            assert_eq!(self.forest.leaves, self.added);
        }
    }

    fn delete(&mut self, u: &mut Unstructured<'_>) {
        if self.leaves.is_empty() {
            return;
        }
        let k = u
            .int_in_range(1..=self.leaves.len().min(MAX_BATCH).max(1))
            .unwrap_or(1);
        let mut dels = Vec::with_capacity(k);
        for _ in 0..k {
            let Some(i) = pick_index(u, self.leaves.len()) else {
                return;
            };
            let h = self.leaves[i];
            if !dels.contains(&h) {
                dels.push(h);
            }
        }
        if dels.is_empty() {
            return;
        }
        if self.forest.modify(&[], &dels).is_ok() {
            self.leaves.retain(|h| !dels.contains(h));
            // Deletes do not shrink MemForest::leaves (ever-added counter).
            assert_eq!(self.forest.leaves, self.added);
        }
    }

    fn prove_verify(&self, u: &mut Unstructured<'_>) {
        if self.leaves.is_empty() {
            return;
        }
        let k = u
            .int_in_range(1..=self.leaves.len().min(MAX_BATCH).max(1))
            .unwrap_or(1);
        let mut targets = Vec::with_capacity(k);
        for _ in 0..k {
            let Some(i) = pick_index(u, self.leaves.len()) else {
                return;
            };
            let h = self.leaves[i];
            if !targets.contains(&h) {
                targets.push(h);
            }
        }
        if let Ok(proof) = self.forest.prove(&targets) {
            assert_eq!(self.forest.verify(&proof, &targets), Ok(true));
        }
    }

    fn grab(&self, u: &mut Unstructured<'_>) {
        if self.forest.leaves == 0 {
            return;
        }
        let pos = u
            .int_in_range(0u64..=self.forest.leaves.saturating_sub(1))
            .unwrap_or(0);
        let _ = self.forest.grab_node(pos);
        // Also try a translated / high position for error paths.
        let weird = u.arbitrary::<u64>().unwrap_or(0);
        let _ = self.forest.grab_node(weird);
    }

    fn replay_roundtrip(&self) {
        let mut buf = Vec::new();
        if self.forest.serialize(&mut buf).is_err() {
            return;
        }
        if let Ok(decoded) = AccMemForest::deserialize(buf.as_slice()) {
            assert_eq!(decoded.leaves, self.forest.leaves);
            assert_eq!(decoded.get_roots().len(), self.forest.get_roots().len());
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let mut session = Session::new();

    limited_while(&mut u, 10_000, |u| {
        call_one_of(u, 5, |idx, u| match idx {
            0 => session.add(u),
            1 => session.delete(u),
            2 => session.prove_verify(u),
            3 => session.grab(u),
            4 => session.replay_roundtrip(),
            _ => {}
        });
    });
});
