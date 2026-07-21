// SPDX-License-Identifier: MIT OR Apache-2.0

//! Thin wrappers so the standalone fuzz package can exercise crate-private
//! position helpers without exporting them from normal builds.

use crate::node_hash::AccumulatorHash;
use crate::util;

pub fn tree_rows(n: u64) -> Result<u8, String> {
    util::tree_rows(n)
}

pub fn translate(pos: u64, from_rows: u8, to_rows: u8) -> Result<u64, String> {
    util::translate(pos, from_rows, to_rows)
}

pub fn detect_row(pos: u64, forest_rows: u8) -> Result<u8, String> {
    util::detect_row(pos, forest_rows)
}

pub fn detect_offset(pos: u64, num_leaves: u64) -> Result<(u8, u8, u64), String> {
    util::detect_offset(pos, num_leaves)
}

pub fn detect_offset_pollard(pos: u64, num_leaves: u64) -> Result<(u8, u8, u64), String> {
    util::detect_offset_pollard(pos, num_leaves)
}

pub fn is_root_position(position: u64, num_leaves: u64, forest_rows: u8) -> Result<bool, String> {
    util::is_root_position(position, num_leaves, forest_rows)
}

pub fn remove_bit(val: u64, bit: u64) -> Result<u64, String> {
    util::remove_bit(val, bit)
}

pub fn calc_next_pos(position: u64, del_pos: u64, forest_rows: u8) -> Result<u64, String> {
    util::calc_next_pos(position, del_pos, forest_rows)
}

pub fn detwin(nodes: Vec<u64>, forest_rows: u8) -> Result<Vec<u64>, String> {
    util::detwin(nodes, forest_rows)
}

pub fn start_position_at_row(row: u8, forest_rows: u8) -> Result<u64, String> {
    util::start_position_at_row(row, forest_rows)
}

pub fn children(pos: u64, forest_rows: u8) -> Result<u64, String> {
    util::children(pos, forest_rows)
}

pub fn left_child(pos: u64, forest_rows: u8) -> Result<u64, String> {
    util::left_child(pos, forest_rows)
}

pub fn right_child(pos: u64, forest_rows: u8) -> Result<u64, String> {
    util::right_child(pos, forest_rows)
}

pub fn parent(pos: u64, forest_rows: u8) -> Result<u64, String> {
    util::parent(pos, forest_rows)
}

pub fn parent_many(pos: u64, rise: u8, forest_rows: u8) -> Result<u64, String> {
    util::parent_many(pos, rise, forest_rows)
}

pub fn is_ancestor(higher_pos: u64, lower_pos: u64, forest_rows: u8) -> Result<bool, String> {
    util::is_ancestor(higher_pos, lower_pos, forest_rows)
}

pub fn root_position(num_leaves: u64, row: u8, forest_rows: u8) -> Result<u64, String> {
    util::root_position(num_leaves, row, forest_rows)
}

pub fn max_position_at_row(row: u8, total_rows: u8, num_leaves: u64) -> Result<u64, String> {
    util::max_position_at_row(row, total_rows, num_leaves)
}

pub fn get_proof_positions(
    targets: &[u64],
    num_leaves: u64,
    forest_rows: u8,
) -> Result<Vec<u64>, String> {
    util::get_proof_positions(targets, num_leaves, forest_rows)
}

pub fn roots_to_destroy<Hash: AccumulatorHash>(
    num_adds: u64,
    num_leaves: u64,
    orig_roots: &[Hash],
) -> Result<Vec<u64>, String> {
    util::roots_to_destroy(num_adds, num_leaves, orig_roots)
}

pub fn is_left_niece(position: u64) -> bool {
    util::is_left_niece(position)
}

pub fn left_sibling(position: u64) -> u64 {
    util::left_sibling(position)
}

pub fn is_root_populated(row: u8, num_leaves: u64) -> Result<bool, String> {
    util::is_root_populated(row, num_leaves)
}

pub fn num_roots(leaves: u64) -> usize {
    util::num_roots(leaves)
}

pub fn is_right_sibling(node: u64, next: u64) -> bool {
    util::is_right_sibling(node, next)
}
