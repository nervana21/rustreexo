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

struct Session {
    stump: AccStump,
    forest: AccMemForest,
    /// Currently present leaf hashes.
    leaves: Vec<AccHash>,
    /// Total successful additions; matches Stump/MemForest ever-added counters.
    added: u64,
    cached_proof: Option<(AccProof, Vec<AccHash>)>,
}

impl Session {
    fn new() -> Self {
        Self {
            stump: AccStump::new(),
            forest: AccMemForest::new(),
            leaves: Vec::new(),
            added: 0,
            cached_proof: None,
        }
    }

    fn grow(&mut self, u: &mut Unstructured<'_>) {
        if self.leaves.len() >= MAX_LEAVES {
            return;
        }
        let room = MAX_LEAVES - self.leaves.len();
        let n = u.int_in_range(1..=room.min(MAX_BATCH).max(1)).unwrap_or(1);
        let mut adds = Vec::with_capacity(n);
        for _ in 0..n {
            let seed = u.arbitrary::<u8>().unwrap_or(0);
            // Prefer unique non-empty hashes so mem_forest map stays usable.
            let h = hash_from_seed(seed.wrapping_add(self.leaves.len() as u8).max(1));
            // MemForest rejects duplicate leaf hashes; Stump does not.
            // Drop dups so a soft-fail cannot leave only one side updated.
            if self.leaves.contains(&h) || adds.contains(&h) {
                continue;
            }
            adds.push(h);
        }
        if adds.is_empty() {
            return;
        }

        let Ok((new_stump, update_data)) = self.stump.modify(&adds, &[], &AccProof::default())
        else {
            return;
        };
        // MemForest first: on Err, session stump is still untouched.
        if self.forest.modify(&adds, &[]).is_err() {
            return;
        }

        // Proof::update must see every modify since the proof was cached.
        // Grow without updating would leave a stale proof and false-fail later.
        if let Some((proof, cached_hashes)) = self.cached_proof.take() {
            match proof.update(
                cached_hashes,
                adds.clone(),
                Vec::new(),
                Vec::new(),
                update_data,
            ) {
                Ok((updated, new_cached)) => {
                    assert_eq!(
                        new_stump.verify(&updated, &new_cached),
                        Ok(true),
                        "cached proof must verify after grow"
                    );
                    self.cached_proof = Some((updated, new_cached));
                }
                Err(_) => {
                    // Drop cache if this add cannot keep the proof current.
                }
            }
        }

        self.stump = new_stump;
        self.added += adds.len() as u64;
        self.leaves.extend(adds);
        // Stump/MemForest::leaves are ever-added, not live count.
        assert_eq!(self.stump.leaves, self.added);
        assert_eq!(self.forest.leaves, self.added);
    }

    fn cache_proof(&mut self, u: &mut Unstructured<'_>) {
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
        if targets.is_empty() {
            return;
        }
        if let Ok(proof) = self.forest.prove(&targets) {
            assert_eq!(
                self.stump.verify(&proof, &targets),
                Ok(true),
                "fresh mem_forest proof must verify on stump"
            );
            self.cached_proof = Some((proof, targets));
        }
    }

    fn subset_and_verify(&self, u: &mut Unstructured<'_>) {
        let Some((proof, dels)) = &self.cached_proof else {
            return;
        };
        if proof.targets.is_empty() {
            return;
        }
        let take = u.int_in_range(1..=proof.targets.len()).unwrap_or(1);
        let subset_targets: Vec<u64> = proof.targets.iter().copied().take(take).collect();
        let Ok(subset) = proof.get_proof_subset(dels, &subset_targets, self.stump.leaves) else {
            return;
        };
        let subset_hashes: Vec<_> = subset_targets
            .iter()
            .filter_map(|t| proof.targets.iter().position(|x| x == t).map(|i| dels[i]))
            .collect();
        if subset_hashes.len() != subset_targets.len() {
            return;
        }
        assert_eq!(
            self.stump.verify(&subset, &subset_hashes),
            Ok(true),
            "proof subset must verify"
        );
    }

    fn update_cached_proof(&mut self, u: &mut Unstructured<'_>) {
        let Some((proof, cached_hashes)) = self.cached_proof.take() else {
            return;
        };

        // Optional delete of a non-cached leaf so the update path still runs.
        let mut del_hashes = Vec::new();
        let mut del_proof = AccProof::default();
        if self.leaves.len() > cached_hashes.len() && u.arbitrary().unwrap_or(false) {
            if let Some(i) = pick_index(u, self.leaves.len()) {
                let h = self.leaves[i];
                if !cached_hashes.contains(&h) {
                    if let Ok(p) = self.forest.prove(&[h]) {
                        del_hashes.push(h);
                        del_proof = p;
                    }
                }
            }
        }
        let block_targets = del_proof.targets.clone();

        let room = MAX_LEAVES.saturating_sub(self.leaves.len());
        let n_add = if room == 0 {
            0
        } else {
            u.int_in_range(0..=room.min(MAX_BATCH)).unwrap_or(0)
        };
        let mut add_hashes = Vec::with_capacity(n_add);
        for _ in 0..n_add {
            let seed = u.arbitrary::<u8>().unwrap_or(1).max(1);
            let h = hash_from_seed(seed.wrapping_add(self.leaves.len() as u8).max(1));
            // Skip hashes still live after this block's deletes (MemForest rejects dups).
            if (!del_hashes.contains(&h) && self.leaves.contains(&h)) || add_hashes.contains(&h)
            {
                continue;
            }
            add_hashes.push(h);
        }

        let Ok((new_stump, update_data)) = self.stump.modify(&add_hashes, &del_hashes, &del_proof)
        else {
            self.cached_proof = Some((proof, cached_hashes));
            return;
        };

        // remembers indexes into add_hashes (new UTXOs to also cache), not
        // into the already-cached targets kept by update_proof_remove/remap.
        let mut remembers = Vec::new();
        for i in 0..add_hashes.len() as u64 {
            if u.arbitrary().unwrap_or(false) {
                remembers.push(i);
            }
        }
        // update() consumes self; clone so Err can restore the cached proof.
        match proof.clone().update(
            cached_hashes.clone(),
            add_hashes.clone(),
            block_targets,
            remembers,
            update_data,
        ) {
            Ok((updated, new_cached)) => {
                assert_eq!(
                    new_stump.verify(&updated, &new_cached),
                    Ok(true),
                    "updated proof must verify"
                );
                // Same add/del already accepted by Stump + proof.update; forest
                // must agree. Soft-return here would desync (del may have applied).
                self.forest
                    .modify(&add_hashes, &del_hashes)
                    .expect("mem_forest modify after successful stump modify");
                self.leaves.retain(|h| !del_hashes.contains(h));
                self.added += add_hashes.len() as u64;
                self.leaves.extend(add_hashes);
                self.stump = new_stump;
                assert_eq!(self.stump.leaves, self.added);
                assert_eq!(self.forest.leaves, self.added);
                self.cached_proof = Some((updated, new_cached));
            }
            Err(_) => {
                self.cached_proof = Some((proof, cached_hashes));
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let mut session = Session::new();

    limited_while(&mut u, 10_000, |u| {
        call_one_of(u, 4, |idx, u| match idx {
            0 => session.grow(u),
            1 => session.cache_proof(u),
            2 => session.subset_and_verify(u),
            3 => session.update_cached_proof(u),
            _ => {}
        });
    });
});
