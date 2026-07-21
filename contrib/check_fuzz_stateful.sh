#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0

# Static check: every fuzz target must use Floresta-style limited_while.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${REPO_ROOT}/fuzz/fuzz_targets"

missing=()
for target in "${TARGET_DIR}"/*.rs; do
  [[ -f "${target}" ]] || continue
  if ! rg -q 'limited_while' "${target}"; then
    missing+=("$(basename "${target}")")
  fi
done

if ((${#missing[@]})); then
  echo "Non-stateful fuzz targets (missing limited_while):" >&2
  printf '  %s\n' "${missing[@]}" >&2
  exit 1
fi

echo "All fuzz targets use limited_while."
