#!/usr/bin/env bash
#
# Build the contracts so their identity is a fact about the SOURCE, not about
# the machine that compiled it.
#
# WHY THIS SCRIPT EXISTS
#
# A contract's address is BLAKE3(BLAKE3(wasm) || params), so the compiled bytes
# ARE the contract. Release binaries embed panic locations as `file:line`, and
# for dependencies those are ABSOLUTE paths into the build machine's cargo
# registry. So `/home/ian/.cargo/registry/...` was compiled into every contract
# this project shipped, and a build on any other machine -- a CI runner at
# `/home/runner/...`, another developer, a reproducibility check -- produced a
# different code hash and therefore a DIFFERENT CONTRACT.
#
# That was not a theory. `webapp/src/keys.rs` pins the derived contract ids;
# the moment CI was fixed so that test actually ran, it failed, because the
# runner's build and nova's build were two different contracts. Nobody could
# verify what was deployed, because nobody else could reproduce it.
#
# `--remap-path-prefix` rewrites those roots to fixed names, and the check at
# the end is fail-closed: if any build-machine path survives into the bytes,
# the build fails rather than quietly shipping a machine-specific contract.
#
# EVERY build of these contracts must go through here. The flags are part of
# the contract's identity, so a second invocation that sets them differently --
# or not at all -- produces a different contract while looking like the same
# command. That is why the Makefile, CI and the deploy script all call this
# rather than each spelling out `cargo build`.
#
# Usage: scripts/build-contracts.sh [target-dir]

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

TARGET_DIR="${1:-$REPO/target}"
CONTRACT_TARGET=wasm32-unknown-unknown

CARGO_DIR="${CARGO_HOME:-$HOME/.cargo}"
RUSTUP_DIR="${RUSTUP_HOME:-$HOME/.rustup}"

# The order matters only in that each root is remapped to a name that is the
# same on every machine. The names themselves are arbitrary and are now part of
# the contract's identity: changing one re-keys every contract.
export CARGO_BUILD_RUSTFLAGS="\
--remap-path-prefix=$CARGO_DIR=/cargo \
--remap-path-prefix=$RUSTUP_DIR=/rustup \
--remap-path-prefix=$REPO=/build"

cargo build --target "$CONTRACT_TARGET" \
  -p bitcoin-address-contract -p bitcoin-tip-contract \
  --features contract --release --target-dir "$TARGET_DIR"

OUT="$TARGET_DIR/$CONTRACT_TARGET/release"

# Fail closed. An allow-list of what a path in these bytes may look like would
# need to enumerate every shape a path can take; this instead names the roots
# that are known to VARY and refuses if any of them survived. A root that
# varies and is not listed here is the next instance of this bug.
for f in "$OUT"/bitcoin_address_contract.wasm "$OUT"/bitcoin_tip_contract.wasm; do
  for probe in "$CARGO_DIR" "$RUSTUP_DIR" "$REPO" "${HOME:-/nonexistent}"; do
    if grep -qaF -- "$probe" "$f"; then
      echo "REFUSING: $(basename "$f") contains the build-machine path '$probe'." >&2
      echo "  Its code hash is therefore specific to this machine, and the contract" >&2
      echo "  it addresses cannot be reproduced anywhere else. Add a remap for that" >&2
      echo "  root above." >&2
      exit 1
    fi
  done
  # A path belonging to some other user means a root nobody remapped -- a
  # vendored artifact, a build script writing its own path, a dependency
  # baking one in. Same consequence, so same refusal.
  if grep -qaE -- '/(home|Users)/[A-Za-z0-9._-]+/' "$f"; then
    echo "REFUSING: $(basename "$f") contains a home-directory path." >&2
    grep -aoE -- '/(home|Users)/[A-Za-z0-9._/-]{0,60}' "$f" | sort -u | head >&2
    exit 1
  fi
done

echo "contracts built, with no build-machine path in either:"
for f in "$OUT"/bitcoin_*_contract.wasm; do
  echo "  $(b3sum --no-names "$f")  $(basename "$f")"
done
