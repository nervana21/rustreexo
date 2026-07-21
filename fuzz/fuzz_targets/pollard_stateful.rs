// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use rustreexo::pollard::PollardAddition;
use rustreexo_fuzz::hash_from_seed;
use rustreexo_fuzz::stateful::call_one_of;
use rustreexo_fuzz::stateful::limited_while;
use rustreexo_fuzz::stateful::pick_index;
use rustreexo_fuzz::AccHash;
use rustreexo_fuzz::AccPollard;
use rustreexo_fuzz::AccProof;
use rustreexo_fuzz::MAX_BATCH;
use rustreexo_fuzz::MAX_LEAVES;

struct Session {
    pollard: AccPollard,
    /// Currently present leaf hashes (for prove/delete).
    leaves: Vec<AccHash>,
    /// Total successful additions; matches [`Pollard::leaves`] (ever-added).
    added: u64,
}

impl Session {
    fn new() -> Self {
        Self {
            pollard: AccPollard::new(),
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
        let mut batch = Vec::with_capacity(n);
        let mut adds = Vec::with_capacity(n);
        for _ in 0..n {
            let seed = u.arbitrary::<u8>().unwrap_or(0);
            let hash = hash_from_seed(seed.wrapping_add(self.leaves.len() as u8).max(1));
            let remember = u.arbitrary().unwrap_or(true);
            batch.push(PollardAddition { hash, remember });
            adds.push(hash);
        }
        if self
            .pollard
            .modify(&batch, &[], AccProof::default())
            .is_ok()
        {
            self.added += adds.len() as u64;
            self.leaves.extend(adds);
            // Pollard::leaves is ever-added, not live count.
            assert_eq!(self.pollard.leaves(), self.added);
        }
    }

    fn prove_verify(&self, u: &mut Unstructured<'_>) {
        if self.leaves.is_empty() {
            return;
        }
        let Some(i) = pick_index(u, self.leaves.len()) else {
            return;
        };
        let leaf = self.leaves[i];
        if let Ok(proof) = self.pollard.prove_single(leaf) {
            assert_eq!(self.pollard.verify(&proof, &[leaf]), Ok(true));
        }
    }

    fn verify_and_ingest(&mut self, u: &mut Unstructured<'_>) {
        if self.leaves.is_empty() {
            return;
        }
        let Some(i) = pick_index(u, self.leaves.len()) else {
            return;
        };
        let leaf = self.leaves[i];
        let Ok(proof) = self.pollard.prove_single(leaf) else {
            return;
        };
        let remembers = [0u64];
        let _ = self.pollard.verify_and_ingest(proof, &[leaf], &remembers);
    }

    fn delete(&mut self, u: &mut Unstructured<'_>) {
        if self.leaves.is_empty() {
            return;
        }
        let Some(i) = pick_index(u, self.leaves.len()) else {
            return;
        };
        let leaf = self.leaves[i];
        let Ok(proof) = self.pollard.prove_single(leaf) else {
            return;
        };
        if self.pollard.modify(&[], &[leaf], proof).is_ok() {
            self.leaves.remove(i);
            // Deletes do not shrink Pollard::leaves (ever-added counter).
            assert_eq!(self.pollard.leaves(), self.added);
        }
    }

    fn prune(&mut self, u: &mut Unstructured<'_>) {
        if self.leaves.is_empty() {
            return;
        }
        // Positions are forest indices; use small leaf positions as candidates.
        let pos = u
            .int_in_range(0u64..=self.pollard.leaves().saturating_sub(1).max(0))
            .unwrap_or(0);
        let _ = self.pollard.prune(&[pos]);
    }

    fn replay_roundtrip(&self) {
        let mut buf = Vec::new();
        if self.pollard.serialize(&mut buf).is_err() {
            return;
        }
        if let Ok(decoded) = AccPollard::deserialize(&mut buf.as_slice()) {
            assert_eq!(decoded.leaves(), self.pollard.leaves());
            assert_eq!(decoded.roots(), self.pollard.roots());
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let mut session = Session::new();

    limited_while(&mut u, 10_000, |u| {
        call_one_of(u, 6, |idx, u| match idx {
            0 => session.add(u),
            1 => session.prove_verify(u),
            2 => session.verify_and_ingest(u),
            3 => session.delete(u),
            4 => session.prune(u),
            5 => session.replay_roundtrip(),
            _ => {}
        });
    });
});
