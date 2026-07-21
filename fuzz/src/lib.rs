// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared helpers for rustreexo fuzz targets.

pub mod stateful;

use libfuzzer_sys::arbitrary::Unstructured;
use rustreexo::mem_forest::MemForest;
use rustreexo::node_hash::AccumulatorHash;
use rustreexo::node_hash::BitcoinNodeHash;
use rustreexo::pollard::Pollard;
use rustreexo::pollard::PollardAddition;
use rustreexo::proof::Proof;
use rustreexo::stump::Stump;

/// Hard caps to keep fuzzer-induced resource use bounded.
pub const MAX_LEAVES: usize = 256;
pub const MAX_BATCH: usize = 32;
pub const MAX_PROOF_TARGETS: usize = 64;
pub const MAX_PROOF_HASHES: usize = 256;
pub const MAX_WIRE_BYTES: usize = 64 * 1024;
pub const MAX_FOREST_ROWS: u8 = 63;

pub type AccHash = BitcoinNodeHash;
pub type AccProof = Proof<AccHash>;
pub type AccStump = Stump<AccHash>;
pub type AccPollard = Pollard<AccHash>;
pub type AccMemForest = MemForest<AccHash>;

/// Deterministic leaf hash from a small seed.
pub fn hash_from_seed(seed: u8) -> AccHash {
    AccHash::from([seed; 32])
}

/// Prefer concrete hashes; occasionally emit Empty for destroy paths.
pub fn arbitrary_hash(u: &mut Unstructured<'_>) -> AccHash {
    match u.int_in_range(0u8..=15).unwrap_or(0) {
        0 => AccHash::empty(),
        1 => AccHash::placeholder(),
        _ => {
            let mut bytes = [0u8; 32];
            if let Ok(slice) = u.bytes(32) {
                bytes.copy_from_slice(slice);
            } else {
                let seed = u.arbitrary::<u8>().unwrap_or(0);
                bytes = [seed; 32];
            }
            AccHash::from(bytes)
        }
    }
}

pub fn arbitrary_hashes(u: &mut Unstructured<'_>, max: usize) -> Vec<AccHash> {
    let n = u.int_in_range(0..=max).unwrap_or(0);
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(arbitrary_hash(u));
    }
    out
}

pub fn arbitrary_positions(u: &mut Unstructured<'_>, max: usize) -> Vec<u64> {
    let n = u.int_in_range(0..=max).unwrap_or(0);
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(u.arbitrary::<u64>().unwrap_or(0));
    }
    out
}

pub fn clamp_wire(bytes: &[u8]) -> &[u8] {
    if bytes.len() > MAX_WIRE_BYTES {
        &bytes[..MAX_WIRE_BYTES]
    } else {
        bytes
    }
}

pub fn build_proof(u: &mut Unstructured<'_>) -> AccProof {
    let targets = arbitrary_positions(u, MAX_PROOF_TARGETS);
    let hashes = arbitrary_hashes(u, MAX_PROOF_HASHES);
    AccProof::new_with_hash(targets, hashes)
}

pub fn proof_roundtrip(proof: &AccProof) {
    let mut buf = Vec::new();
    proof.serialize(&mut buf).expect("proof serialize");
    let decoded = AccProof::deserialize(buf.as_slice()).expect("proof deserialize");
    assert_eq!(decoded.targets, proof.targets);
    assert_eq!(decoded.hashes, proof.hashes);
}

pub fn stump_roundtrip(stump: &AccStump) {
    let mut buf = Vec::new();
    stump.serialize(&mut buf).expect("stump serialize");
    let decoded = AccStump::deserialize(buf.as_slice()).expect("stump deserialize");
    assert_eq!(decoded.leaves, stump.leaves);
    assert_eq!(decoded.roots, stump.roots);
}

pub fn pollard_roundtrip(pollard: &AccPollard) {
    let mut buf = Vec::new();
    pollard.serialize(&mut buf).expect("pollard serialize");
    let decoded = AccPollard::deserialize(&mut buf.as_slice()).expect("pollard deserialize");
    assert_eq!(decoded.leaves(), pollard.leaves());
    assert_eq!(decoded.roots(), pollard.roots());
}

pub fn mem_forest_roundtrip(forest: &AccMemForest) {
    let mut buf = Vec::new();
    forest.serialize(&mut buf).expect("mem_forest serialize");
    let decoded = AccMemForest::deserialize(buf.as_slice()).expect("mem_forest deserialize");
    assert_eq!(decoded.leaves, forest.leaves);
    assert_eq!(decoded.get_roots().len(), forest.get_roots().len());
    for (a, b) in decoded.get_roots().iter().zip(forest.get_roots().iter()) {
        assert_eq!(a.get_data(), b.get_data());
    }
}

/// Grow a stump with only additions (empty deletes, empty proof).
pub fn stump_add_only(stump: AccStump, adds: &[AccHash]) -> AccStump {
    stump
        .modify(adds, &[], &AccProof::default())
        .map(|(s, _)| s)
        .unwrap_or(stump)
}

pub fn pollard_add_remember_all(pollard: &mut AccPollard, adds: &[AccHash]) {
    let batch: Vec<PollardAddition<AccHash>> = adds
        .iter()
        .copied()
        .map(|hash| PollardAddition {
            hash,
            remember: true,
        })
        .collect();
    let _ = pollard.modify(&batch, &[], AccProof::default());
}

pub fn mem_forest_add_only(forest: &mut AccMemForest, adds: &[AccHash]) {
    let _ = forest.modify(adds, &[]);
}

pub fn stump_root_hashes(stump: &AccStump) -> Vec<AccHash> {
    stump.roots.clone()
}

pub fn pollard_root_hashes(pollard: &AccPollard) -> Vec<AccHash> {
    pollard.roots()
}

pub fn mem_forest_root_hashes(forest: &AccMemForest) -> Vec<AccHash> {
    forest.get_roots().iter().map(|n| n.get_data()).collect()
}

/// Build matching stump/pollard/mem forests from the same addition sequence.
pub fn build_matched_forests(adds: &[AccHash]) -> (AccStump, AccPollard, AccMemForest) {
    let stump = stump_add_only(AccStump::new(), adds);
    let mut pollard = AccPollard::new();
    pollard_add_remember_all(&mut pollard, adds);
    let mut mem = AccMemForest::new();
    mem_forest_add_only(&mut mem, adds);
    (stump, pollard, mem)
}

/// Canonical root set: drop empty placeholders and sort.
///
/// The three accumulators expose roots in different orders (Stump/MemForest by
/// storage order, `Pollard::roots()` by ascending row slot), and MemForest keeps
/// empty placeholder roots the others omit. Roots sit at distinct rows with
/// unique hashes, so a sorted non-empty set is order-independent and sufficient
/// to prove the forests agree.
fn canonical_roots(mut roots: Vec<AccHash>) -> Vec<AccHash> {
    roots.retain(|h| !h.is_empty());
    roots.sort_unstable();
    roots
}

pub fn assert_roots_match(stump: &AccStump, pollard: &AccPollard, mem: &AccMemForest) {
    assert_eq!(stump.leaves, pollard.leaves());
    assert_eq!(stump.leaves, mem.leaves);

    let stump_roots = canonical_roots(stump_root_hashes(stump));
    let pollard_roots = canonical_roots(pollard_root_hashes(pollard));
    let mem_roots = canonical_roots(mem_forest_root_hashes(mem));

    assert_eq!(stump_roots, pollard_roots);
    assert_eq!(stump_roots, mem_roots);
}
