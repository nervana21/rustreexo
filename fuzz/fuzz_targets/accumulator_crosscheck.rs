// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use rustreexo::pollard::PollardAddition;
use rustreexo_fuzz::assert_roots_match;
use rustreexo_fuzz::hash_from_seed;
use rustreexo_fuzz::stateful::call_one_of;
use rustreexo_fuzz::stateful::limited_while;
use rustreexo_fuzz::stateful::pick_index;
use rustreexo_fuzz::AccHash;
use rustreexo_fuzz::AccMemForest;
use rustreexo_fuzz::AccPollard;
use rustreexo_fuzz::AccProof;
use rustreexo_fuzz::AccStump;
use rustreexo_fuzz::MAX_BATCH;
use rustreexo_fuzz::MAX_LEAVES;

struct Session {
    stump: AccStump,
    pollard: AccPollard,
    mem: AccMemForest,
    leaves: Vec<AccHash>,
}

impl Session {
    fn new() -> Self {
        Self {
            stump: AccStump::new(),
            pollard: AccPollard::new(),
            mem: AccMemForest::new(),
            leaves: Vec::new(),
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
            let hash = hash_from_seed(
                seed.wrapping_add(self.leaves.len() as u8).max(1),
            );
            // MemForest rejects duplicate leaf hashes; Stump/Pollard do not.
            // Drop dups so a soft-fail cannot leave only one forest updated.
            if self.leaves.contains(&hash) || adds.contains(&hash) {
                continue;
            }
            adds.push(hash);
        }
        if adds.is_empty() {
            return;
        }

        let Ok((new_stump, _)) = self.stump.modify(&adds, &[], &AccProof::default()) else {
            return;
        };
        let batch: Vec<_> = adds
            .iter()
            .copied()
            .map(|hash| PollardAddition {
                hash,
                remember: true,
            })
            .collect();
        // MemForest first: on Err, Pollard is still untouched.
        if self.mem.modify(&adds, &[]).is_err() {
            return;
        }
        if self
            .pollard
            .modify(&batch, &[], AccProof::default())
            .is_err()
        {
            // MemForest already advanced; soft-return would desync the session.
            panic!("pollard add failed after successful mem add");
        }

        self.stump = new_stump;
        self.leaves.extend(adds);
        assert_roots_match(&self.stump, &self.pollard, &self.mem);
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

        let Ok(proof) = self.mem.prove(&dels) else {
            return;
        };
        assert_eq!(self.stump.verify(&proof, &dels), Ok(true));
        assert_eq!(self.pollard.verify(&proof, &dels), Ok(true));
        assert_eq!(self.mem.verify(&proof, &dels), Ok(true));

        let Ok((new_stump, _)) = self.stump.modify(&[], &dels, &proof) else {
            return;
        };
        // MemForest first: on Err, Pollard is still untouched.
        if self.mem.modify(&[], &dels).is_err() {
            return;
        }
        if let Err(e) = self.pollard.modify(&[], &dels, proof) {
            panic!(
                "pollard delete failed after successful mem delete: {:?}",
                e
            );
        }

        self.stump = new_stump;
        self.leaves.retain(|h| !dels.contains(h));
        assert_roots_match(&self.stump, &self.pollard, &self.mem);
    }

    fn cross_prove(&self, u: &mut Unstructured<'_>) {
        if self.leaves.is_empty() {
            return;
        }
        let Some(i) = pick_index(u, self.leaves.len()) else {
            return;
        };
        let leaf = self.leaves[i];

        if let Ok(proof) = self.mem.prove(&[leaf]) {
            assert_eq!(self.stump.verify(&proof, &[leaf]), Ok(true));
            assert_eq!(self.pollard.verify(&proof, &[leaf]), Ok(true));
            assert_eq!(self.mem.verify(&proof, &[leaf]), Ok(true));
        }
        if let Ok(proof) = self.pollard.prove_single(leaf) {
            assert_eq!(self.stump.verify(&proof, &[leaf]), Ok(true));
            assert_eq!(self.pollard.verify(&proof, &[leaf]), Ok(true));
            assert_eq!(self.mem.verify(&proof, &[leaf]), Ok(true));
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let mut session = Session::new();

    limited_while(&mut u, 10_000, |u| {
        call_one_of(u, 3, |idx, u| match idx {
            0 => session.add(u),
            1 => session.delete(u),
            2 => session.cross_prove(u),
            _ => {}
        });
    });
});
