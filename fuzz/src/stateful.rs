// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stateful API fuzz helpers, modeled after Bitcoin Core's `test/fuzz/util.h`
//! and Floresta's `fuzz/src/stateful.rs`.

use libfuzzer_sys::arbitrary::Unstructured;

/// Default upper bound for [`limited_while`] iteration counts.
pub const DEFAULT_MAX_OPS: usize = 10_000;

/// Run `body` while unstructured input yields `true`, at most `max_iters` times.
pub fn limited_while<F>(u: &mut Unstructured<'_>, max_iters: usize, mut body: F)
where
    F: FnMut(&mut Unstructured<'_>),
{
    for _ in 0..max_iters {
        if !u.arbitrary().unwrap_or(false) {
            break;
        }
        body(u);
    }
}

/// Invoke exactly one of `choices`, chosen uniformly at random.
pub fn call_one_of(
    u: &mut Unstructured<'_>,
    choice_count: usize,
    mut dispatch: impl FnMut(usize, &mut Unstructured<'_>),
) {
    if choice_count == 0 {
        return;
    }
    let idx = u.int_in_range(0..=choice_count - 1).unwrap_or(0);
    dispatch(idx, u);
}

/// Pick a random element from a non-empty slice.
pub fn pick<'a, T>(u: &mut Unstructured<'_>, items: &'a [T]) -> Option<&'a T> {
    if items.is_empty() {
        return None;
    }
    let idx = u.int_in_range(0..=items.len() - 1).ok()?;
    Some(&items[idx])
}

/// Pick a random index into a non-empty collection.
pub fn pick_index(u: &mut Unstructured<'_>, len: usize) -> Option<usize> {
    if len == 0 {
        return None;
    }
    u.int_in_range(0..=len - 1).ok()
}

/// Consume an optional sub-slice from unstructured input.
pub fn consume_bytes<'a>(u: &mut Unstructured<'a>) -> Option<&'a [u8]> {
    u.arbitrary().ok()
}

/// Default cap on stored fuzz inputs per session.
pub const DEFAULT_INPUT_POOL_CAP: usize = 256;

/// Reusable byte pool for stateful decode/parse fuzz targets.
pub struct InputPool {
    inputs: Vec<Vec<u8>>,
    cap: usize,
}

impl InputPool {
    pub fn new() -> Self {
        Self::with_cap(DEFAULT_INPUT_POOL_CAP)
    }

    pub fn with_cap(cap: usize) -> Self {
        Self {
            inputs: Vec::new(),
            cap,
        }
    }

    pub fn load(&mut self, u: &mut Unstructured<'_>) {
        let Some(bytes) = consume_bytes(u) else {
            return;
        };
        self.push(bytes.to_vec());
    }

    pub fn push(&mut self, bytes: Vec<u8>) {
        if self.inputs.len() >= self.cap {
            return;
        }
        self.inputs.push(bytes);
    }

    pub fn is_empty(&self) -> bool {
        self.inputs.is_empty()
    }

    pub fn len(&self) -> usize {
        self.inputs.len()
    }

    pub fn get(&self, idx: usize) -> Option<&[u8]> {
        self.inputs.get(idx).map(Vec::as_slice)
    }

    /// Prefer a pooled input when available; otherwise consume fresh bytes.
    pub fn pick_or_consume(&self, u: &mut Unstructured<'_>) -> Option<Vec<u8>> {
        if !self.inputs.is_empty() && u.arbitrary().unwrap_or(true) {
            let idx = pick_index(u, self.inputs.len())?;
            Some(self.inputs[idx].clone())
        } else {
            consume_bytes(u).map(<[u8]>::to_vec)
        }
    }
}

impl Default for InputPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Object pool for retaining decoded structures across ops in one input.
pub struct ObjectPool<T> {
    items: Vec<T>,
    cap: usize,
}

impl<T> ObjectPool<T> {
    pub fn new() -> Self {
        Self::with_cap(DEFAULT_INPUT_POOL_CAP)
    }

    pub fn with_cap(cap: usize) -> Self {
        Self {
            items: Vec::new(),
            cap,
        }
    }

    pub fn push(&mut self, item: T) {
        if self.items.len() >= self.cap {
            return;
        }
        self.items.push(item);
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn get(&self, idx: usize) -> Option<&T> {
        self.items.get(idx)
    }

    pub fn get_mut(&mut self, idx: usize) -> Option<&mut T> {
        self.items.get_mut(idx)
    }

    pub fn as_slice(&self) -> &[T] {
        &self.items
    }
}

impl<T> Default for ObjectPool<T> {
    fn default() -> Self {
        Self::new()
    }
}
