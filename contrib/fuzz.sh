#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0

# Run rustreexo libFuzzer targets. On macOS, uses Linux Docker because
# cargo-fuzz's default AddressSanitizer build often hangs at startup on Darwin.
#
# Usage:
#   ./contrib/fuzz.sh [TARGET] [LIBFUZZER_ARGS...]
#
# Examples:
#   ./contrib/fuzz.sh proof_deserialize
#   ./contrib/fuzz.sh proof_deserialize -max_total_time=300
#   FUZZ_MAX_TIME=120 ./contrib/fuzz.sh
#
# Environment:
#   FUZZ_MAX_TIME       Per-target libFuzzer time limit (default: 60)
#   CARGO_FUZZ_VERSION  cargo-fuzz pin (default: 0.13.1)
#   FUZZ_DOCKER_IMAGE   Container image (default: mirror.gcr.io/ubuntu:24.04)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FUZZ_MAX_TIME="${FUZZ_MAX_TIME:-60}"
CARGO_FUZZ_VERSION="${CARGO_FUZZ_VERSION:-0.13.1}"
FUZZ_DOCKER_IMAGE="${FUZZ_DOCKER_IMAGE:-mirror.gcr.io/ubuntu:24.04}"

TARGET="${1:-}"
if [[ -n "$TARGET" ]]; then
  shift
fi
EXTRA_ARGS=("$@")

run_target() {
  local target="$1"
  shift
  local -a extra=("$@")
  local -a libfuzzer_args=(
    "-max_total_time=${FUZZ_MAX_TIME}"
    "-print_final_stats=1"
  )
  if ((${#extra[@]})); then
    libfuzzer_args+=("${extra[@]}")
  fi

  echo "Running fuzz target: ${target}"
  # Build outside timeout: cold ASan compile often exceeds FUZZ_MAX_TIME+slack,
  # and timeout mid-link leaves no artifact (retry loop = same 124 forever).
  env CARGO_PROFILE_RELEASE_LTO=false \
    cargo +nightly fuzz build "${target}"
  # Wall-clock backstop in case libFuzzer never honors -max_total_time.
  timeout "$((FUZZ_MAX_TIME + 30))" \
    env CARGO_PROFILE_RELEASE_LTO=false \
    cargo +nightly fuzz run "${target}" -- "${libfuzzer_args[@]}"
}

run_all_targets() {
  cd "${REPO_ROOT}/fuzz"
  local targets
  targets="$(cargo +nightly fuzz list)"
  for target in ${targets}; do
    run_target "${target}" "${EXTRA_ARGS[@]}"
  done
}

run_native() {
  cd "${REPO_ROOT}/fuzz"
  if ! command -v cargo-fuzz >/dev/null 2>&1; then
    echo "Installing cargo-fuzz ${CARGO_FUZZ_VERSION}..."
    # No --locked: cargo-fuzz's shipped Cargo.lock pins rustix 0.36.5, which
    # uses the `rustc_attrs` cfg removed from current nightly and fails to
    # build. Let cargo resolve a newer, nightly-compatible rustix instead.
    cargo +nightly install cargo-fuzz --version "${CARGO_FUZZ_VERSION}" --force
  fi
  if [[ -n "${TARGET}" ]]; then
    run_target "${TARGET}" "${EXTRA_ARGS[@]}"
  else
    run_all_targets
  fi
}

run_docker() {
  local -a docker_tty=()
  if [[ -t 0 ]]; then
    docker_tty=(-it)
  fi

  docker run --rm "${docker_tty[@]}" \
    -v "${REPO_ROOT}:/rustreexo" \
    -w /rustreexo \
    -e FUZZ_MAX_TIME="${FUZZ_MAX_TIME}" \
    -e CARGO_FUZZ_VERSION="${CARGO_FUZZ_VERSION}" \
    -e TARGET="${TARGET}" \
    -e EXTRA_ARGS="${EXTRA_ARGS[*]:-}" \
    "${FUZZ_DOCKER_IMAGE}" \
    bash -lc '
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl build-essential cmake clang ca-certificates git coreutils
if ! command -v cargo >/dev/null 2>&1; then
  curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly --profile minimal
fi
# shellcheck disable=SC1091
source "$HOME/.cargo/env"
./contrib/fuzz.sh ${TARGET:+"${TARGET}"} ${EXTRA_ARGS}
'
}

case "$(uname -s)" in
  Darwin)
    echo "macOS detected: running fuzz in Linux Docker (native ASan fuzz often hangs on Darwin)."
    run_docker
    ;;
  Linux)
    run_native
    ;;
  *)
    echo "Unsupported OS for fuzzing: $(uname -s). Use Linux or macOS with Docker." >&2
    exit 1
    ;;
esac
