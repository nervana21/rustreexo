// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use rustreexo::fuzz_harness as util;
use rustreexo::node_hash::AccumulatorHash;
use rustreexo::node_hash::BitcoinNodeHash;
use rustreexo_fuzz::stateful::call_one_of;
use rustreexo_fuzz::stateful::limited_while;
use rustreexo_fuzz::stateful::pick;
use rustreexo_fuzz::stateful::ObjectPool;
use rustreexo_fuzz::MAX_FOREST_ROWS;

#[derive(Clone, Copy, Debug)]
struct GeoArgs {
    pos: u64,
    num_leaves: u64,
    forest_rows: u8,
    row: u8,
    bit: u64,
    rise: u8,
}

fn arbitrary_geo(u: &mut Unstructured<'_>) -> GeoArgs {
    GeoArgs {
        pos: u.arbitrary().unwrap_or(0),
        num_leaves: u.arbitrary().unwrap_or(0),
        forest_rows: u.int_in_range(0u8..=MAX_FOREST_ROWS).unwrap_or(0),
        row: u.int_in_range(0u8..=MAX_FOREST_ROWS).unwrap_or(0),
        bit: u.int_in_range(0u64..=64).unwrap_or(0),
        rise: u.int_in_range(0u8..=MAX_FOREST_ROWS).unwrap_or(0),
    }
}

fn exercise(g: GeoArgs) {
    let _ = util::tree_rows(g.num_leaves);
    let _ = util::detect_row(g.pos, g.forest_rows);
    let _ = util::detect_offset(g.pos, g.num_leaves);
    let _ = util::detect_offset_pollard(g.pos, g.num_leaves);
    let _ = util::translate(g.pos, g.forest_rows, g.row);
    let _ = util::translate(g.pos, g.row, g.forest_rows);
    let _ = util::is_root_position(g.pos, g.num_leaves, g.forest_rows);
    let _ = util::remove_bit(g.pos, g.bit);
    let _ = util::calc_next_pos(g.pos, g.num_leaves, g.forest_rows);
    let _ = util::start_position_at_row(g.row, g.forest_rows);
    let _ = util::children(g.pos, g.forest_rows);
    let _ = util::left_child(g.pos, g.forest_rows);
    let _ = util::right_child(g.pos, g.forest_rows);
    let _ = util::parent(g.pos, g.forest_rows);
    let _ = util::parent_many(g.pos, g.rise, g.forest_rows);
    let _ = util::is_ancestor(g.pos, g.num_leaves, g.forest_rows);
    let _ = util::root_position(g.num_leaves, g.row, g.forest_rows);
    let _ = util::max_position_at_row(g.row, g.forest_rows, g.num_leaves);
    let _ = util::get_proof_positions(&[g.pos], g.num_leaves, g.forest_rows);
    let _ = util::detwin(vec![g.pos, g.num_leaves], g.forest_rows);
    let _ = util::is_left_niece(g.pos);
    let _ = util::left_sibling(g.pos);
    let _ = util::is_root_populated(g.row, g.num_leaves);
    let _ = util::num_roots(g.num_leaves);
    let _ = util::is_right_sibling(g.pos, g.num_leaves);

    // Row-63 boundary stress.
    let _ = util::root_position(g.num_leaves, g.row.min(63), 63);
    let _ = util::children(g.pos, 63);
    let _ = util::parent(g.pos, 63);
    let _ = util::translate(g.pos, 10, 63);

    let roots = [
        BitcoinNodeHash::empty(),
        BitcoinNodeHash::from([1; 32]),
        BitcoinNodeHash::placeholder(),
    ];
    let _ = util::roots_to_destroy::<BitcoinNodeHash>(g.bit.min(64), g.num_leaves, &roots);
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let mut pool = ObjectPool::<GeoArgs>::new();

    limited_while(&mut u, 10_000, |u| {
        call_one_of(u, 3, |idx, u| match idx {
            0 => {
                let g = arbitrary_geo(u);
                exercise(g);
                pool.push(g);
            }
            1 => {
                if let Some(g) = pick(u, pool.as_slice()) {
                    exercise(*g);
                }
            }
            2 => {
                // Invalid extremes.
                exercise(GeoArgs {
                    pos: u64::MAX,
                    num_leaves: (1u64 << 63).saturating_add(1),
                    forest_rows: 64,
                    row: 64,
                    bit: 64,
                    rise: 64,
                });
            }
            _ => {}
        });
    });
});
