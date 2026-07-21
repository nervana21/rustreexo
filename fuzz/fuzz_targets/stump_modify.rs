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
use rustreexo_fuzz::AccProof;
use rustreexo_fuzz::AccStump;
use rustreexo_fuzz::MAX_BATCH;
use rustreexo_fuzz::MAX_LEAVES;

#[derive(Clone)]
struct Snapshot {
    stump: AccStump,
    forest: AccMemForest,
    /// Currently present leaf hashes (for prove/delete).
    leaves: Vec<AccHash>,
    /// Total successful additions; matches Stump/MemForest ever-added counters.
    added: u64,
}

struct Session {
    cur: Snapshot,
    undos: Vec<Snapshot>,
}

impl Session {
    fn new() -> Self {
        Self {
            cur: Snapshot {
                stump: AccStump::new(),
                forest: AccMemForest::new(),
                leaves: Vec::new(),
                added: 0,
            },
            undos: Vec::new(),
        }
    }

    fn push_undo(&mut self) {
        if self.undos.len() < 64 {
            self.undos.push(self.cur.clone());
        }
    }

    fn add(&mut self, u: &mut Unstructured<'_>) {
        if self.cur.leaves.len() >= MAX_LEAVES {
            return;
        }
        let room = MAX_LEAVES - self.cur.leaves.len();
        let n = u.int_in_range(1..=room.min(MAX_BATCH).max(1)).unwrap_or(1);
        let mut adds = Vec::with_capacity(n);
        for _ in 0..n {
            let seed = u.arbitrary::<u8>().unwrap_or(0);
            let hash = hash_from_seed(
                seed.wrapping_add(self.cur.leaves.len() as u8).max(1),
            );
            // MemForest rejects duplicate leaf hashes; Stump does not.
            // Drop dups so a soft-fail cannot leave only one side updated.
            if self.cur.leaves.contains(&hash) || adds.contains(&hash) {
                continue;
            }
            adds.push(hash);
        }
        if adds.is_empty() {
            return;
        }
        let Ok((new_stump, _)) = self
            .cur
            .stump
            .modify(&adds, &[], &AccProof::default())
        else {
            return;
        };
        // Clone before in-place MemForest::modify so push_undo still
        // snapshots the pre-modify forest (and soft-fail leaves cur untouched).
        let mut new_forest = self.cur.forest.clone();
        if new_forest.modify(&adds, &[]).is_err() {
            return;
        }
        self.push_undo();
        self.cur.stump = new_stump;
        self.cur.forest = new_forest;
        self.cur.added += adds.len() as u64;
        self.cur.leaves.extend(adds);
        // Stump/MemForest::leaves are ever-added, not live count.
        assert_eq!(self.cur.stump.leaves, self.cur.added);
        assert_eq!(self.cur.forest.leaves, self.cur.added);
    }

    fn delete(&mut self, u: &mut Unstructured<'_>) {
        if self.cur.leaves.is_empty() {
            return;
        }
        let k = u
            .int_in_range(1..=self.cur.leaves.len().min(MAX_BATCH).max(1))
            .unwrap_or(1);
        let mut dels = Vec::with_capacity(k);
        for _ in 0..k {
            let Some(i) = pick_index(u, self.cur.leaves.len()) else {
                return;
            };
            let h = self.cur.leaves[i];
            if !dels.contains(&h) {
                dels.push(h);
            }
        }
        if dels.is_empty() {
            return;
        }
        let Ok(proof) = self.cur.forest.prove(&dels) else {
            return;
        };
        assert_eq!(self.cur.stump.verify(&proof, &dels), Ok(true));
        let Ok((new_stump, _)) = self.cur.stump.modify(&[], &dels, &proof) else {
            return;
        };
        let mut new_forest = self.cur.forest.clone();
        if new_forest.modify(&[], &dels).is_err() {
            return;
        }
        self.push_undo();
        self.cur.leaves.retain(|h| !dels.contains(h));
        self.cur.stump = new_stump;
        self.cur.forest = new_forest;
        // Deletes do not shrink ever-added counters.
        assert_eq!(self.cur.stump.leaves, self.cur.added);
        assert_eq!(self.cur.forest.leaves, self.cur.added);
    }

    fn verify_random(&self, u: &mut Unstructured<'_>) {
        if self.cur.leaves.is_empty() {
            let _ = self.cur.stump.verify(&AccProof::default(), &[]);
            return;
        }
        let k = u
            .int_in_range(1..=self.cur.leaves.len().min(MAX_BATCH).max(1))
            .unwrap_or(1);
        let mut targets = Vec::with_capacity(k);
        for _ in 0..k {
            let Some(i) = pick_index(u, self.cur.leaves.len()) else {
                return;
            };
            let h = self.cur.leaves[i];
            if !targets.contains(&h) {
                targets.push(h);
            }
        }
        if let Ok(proof) = self.cur.forest.prove(&targets) {
            assert_eq!(self.cur.stump.verify(&proof, &targets), Ok(true));
        }
    }

    fn undo(&mut self) {
        if let Some(old) = self.undos.pop() {
            self.cur = old;
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let mut session = Session::new();

    limited_while(&mut u, 10_000, |u| {
        call_one_of(u, 4, |idx, u| match idx {
            0 => session.add(u),
            1 => session.delete(u),
            2 => session.verify_random(u),
            3 => session.undo(),
            _ => {}
        });
    });
});
