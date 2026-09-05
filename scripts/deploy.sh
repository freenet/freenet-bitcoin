#!/usr/bin/env bash
#
# Deploy the bridge and the webapp from ONE build of ONE tree.
#
# WHY THIS IS A SINGLE SCRIPT
#
# A contract's address is BLAKE3(BLAKE3(wasm) || params). The bridge writes
# observations to an address derived from the WASM installed under
# /var/lib/btcbridge/contracts; the webapp derives one from the WASM it was
# built with. Deploying those on different days, from different trees, or from
# a `target/` that has drifted, gives them different bytes and therefore
# different addresses -- and nothing errors. The webapp reads a contract nobody
# writes to and renders the page it renders for an address with no activity.
#
# So the two halves are not two tasks. This script builds the contracts ONCE,
# into a throwaway target directory, and installs those exact bytes into both
# places, refusing to continue if they ever differ.
#
# The throwaway target directory is not caution, it is required: a long-lived
# `target/` silently changes a contract's identity, because `cargo clean -p` of
# the workspace crates still reuses dependency artifacts and under fat LTO
# those yield a different module. Two fresh clones of one commit agree with
# each other and disagreed with a working tree, which is how that was found.
#
# Usage:
#   scripts/deploy.sh                 # the whole thing
#   scripts/deploy.sh --dry-run       # build and check, change nothing
#   scripts/deploy.sh --skip-preflight
#   scripts/deploy.sh --bridge-only | --webapp-only

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

CONTRACT_TARGET=wasm32-unknown-unknown
CONTRACT_DIR=/var/lib/btcbridge/contracts
BRIDGE_BIN=/usr/local/bin/bitcoin-freenet-bridge
BRIDGE_CFG=/etc/bitcoin-freenet-bridge.toml
SERVICE=bitcoin-freenet-bridge.service
# Fixed for the life of the app. `fdev website update` republishes to the same
# contract; `publish` would mint a new one and orphan every link to this one.
WEBSITE_KEY=freenet-bitcoin

DRY_RUN=0
SKIP_PREFLIGHT=0
DO_BRIDGE=1
DO_WEBAPP=1
for arg in "$@"; do
  case "$arg" in
    --dry-run)        DRY_RUN=1 ;;
    --skip-preflight) SKIP_PREFLIGHT=1 ;;
    --bridge-only)    DO_WEBAPP=0 ;;
    --webapp-only)    DO_BRIDGE=0 ;;
    -h|--help)        sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die()  { printf '\n\033[31mREFUSING: %s\033[0m\n' "$*" >&2; exit 1; }
run()  { if [ "$DRY_RUN" = 1 ]; then echo "  would run: $*"; else "$@"; fi }

# ---------------------------------------------------------------------------
step "Preflight"
# ---------------------------------------------------------------------------
if [ "$SKIP_PREFLIGHT" = 1 ]; then
  echo "  skipped by request"
else
  cargo make preflight >/dev/null
  echo "  fmt, clippy, tests, contract imports: OK"
fi

# ---------------------------------------------------------------------------
step "Build the contracts from a clean target directory"
# ---------------------------------------------------------------------------
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT
./scripts/build-contracts.sh "$BUILD_DIR" >/dev/null
OUT="$BUILD_DIR/$CONTRACT_TARGET/release"

NEW_ADDRESS_HASH=$(b3sum --no-names "$OUT/bitcoin_address_contract.wasm")
NEW_TIP_HASH=$(b3sum --no-names "$OUT/bitcoin_tip_contract.wasm")
echo "  address contract: $NEW_ADDRESS_HASH"
echo "  tip contract:     $NEW_TIP_HASH"

# ---------------------------------------------------------------------------
step "Check what the bridge is running now"
# ---------------------------------------------------------------------------
OLD_ADDRESS_HASH=""
OLD_TIP_HASH=""
if [ -f "$CONTRACT_DIR/bitcoin_address_contract.wasm" ]; then
  OLD_ADDRESS_HASH=$(b3sum --no-names "$CONTRACT_DIR/bitcoin_address_contract.wasm")
  OLD_TIP_HASH=$(b3sum --no-names "$CONTRACT_DIR/bitcoin_tip_contract.wasm")
  echo "  address contract: $OLD_ADDRESS_HASH"
  echo "  tip contract:     $OLD_TIP_HASH"
else
  echo "  nothing installed yet"
fi

# A generation being replaced must be recorded in legacy/ FIRST. The migration
# probe walks that list to carry old observations forward; a generation left
# out of it is not migrated, and its state is orphaned with no error anywhere.
for pair in "address:$OLD_ADDRESS_HASH:$NEW_ADDRESS_HASH" "tip:$OLD_TIP_HASH:$NEW_TIP_HASH"; do
  what=${pair%%:*}; rest=${pair#*:}; old=${rest%%:*}; new=${rest#*:}
  [ -n "$old" ] || continue
  [ "$old" != "$new" ] || continue
  if ! grep -q "$old" "legacy/${what}_contract.toml"; then
    die "the bridge is running ${what} generation $old, which this build replaces,
   and legacy/${what}_contract.toml does not record it. Add it there BEFORE
   deploying, or the observations under it are orphaned with no error."
  fi
  echo "  ${what}: $old -> $new (outgoing generation is recorded in legacy/)"
done

# The same check the webapp bundle carries, applied to the bytes about to be
# installed: never deploy a generation the project has already retired.
for pair in "address:$NEW_ADDRESS_HASH" "tip:$NEW_TIP_HASH"; do
  what=${pair%%:*}; new=${pair#*:}
  if grep -q "$new" "legacy/${what}_contract.toml"; then
    die "the ${what} contract this tree builds ($new) is recorded in legacy/ as
   SUPERSEDED. Deploying it would move the bridge backwards onto a retired
   generation."
  fi
done

if [ "$DO_BRIDGE" = 1 ]; then
  # -------------------------------------------------------------------------
  step "Install the bridge"
  # -------------------------------------------------------------------------
  cargo build --release -p bitcoin-freenet-bridge >/dev/null 2>&1
  run sudo install -m 0755 target/release/bitcoin-freenet-bridge "$BRIDGE_BIN"
  run sudo install -m 0644 -o btcbridge -g btcbridge \
      "$OUT/bitcoin_address_contract.wasm" "$CONTRACT_DIR/bitcoin_address_contract.wasm"
  run sudo install -m 0644 -o btcbridge -g btcbridge \
      "$OUT/bitcoin_tip_contract.wasm" "$CONTRACT_DIR/bitcoin_tip_contract.wasm"
  run sudo systemctl restart "$SERVICE"
  if [ "$DRY_RUN" = 0 ]; then
    sleep 5
    systemctl is-active --quiet "$SERVICE" || die "$SERVICE did not come back up"
    echo "  $SERVICE restarted"

    # -----------------------------------------------------------------------
    step "Confirm the bridge published its generation pointers"
    # -----------------------------------------------------------------------
    # This is the check the whole mechanism exists for, run before the webapp
    # is built: the pointer is what a reader follows, so if it did not move,
    # nothing else in this deploy matters.
    sudo -u btcbridge "$BRIDGE_BIN" --config "$BRIDGE_CFG" --print-generation
  fi
fi

if [ "$DO_WEBAPP" = 1 ]; then
  # -------------------------------------------------------------------------
  step "Build the webapp from the SAME contract bytes"
  # -------------------------------------------------------------------------
  mkdir -p webapp/contracts
  cp "$OUT/bitcoin_address_contract.wasm" webapp/contracts/
  cp "$OUT/bitcoin_tip_contract.wasm" webapp/contracts/

  # The gate. Everything above can be right and this still wrong -- a stray
  # `cargo make build-contracts` between the two copies is enough -- so the
  # bytes are compared where they finally sit, not where they came from.
  if [ "$DO_BRIDGE" = 1 ] && [ "$DRY_RUN" = 0 ]; then
    INSTALLED_ADDRESS=$(b3sum --no-names "$CONTRACT_DIR/bitcoin_address_contract.wasm")
    INSTALLED_TIP=$(b3sum --no-names "$CONTRACT_DIR/bitcoin_tip_contract.wasm")
    EMBEDDED_ADDRESS=$(b3sum --no-names webapp/contracts/bitcoin_address_contract.wasm)
    EMBEDDED_TIP=$(b3sum --no-names webapp/contracts/bitcoin_tip_contract.wasm)
    [ "$INSTALLED_ADDRESS" = "$EMBEDDED_ADDRESS" ] || die \
      "the bridge would use address contract $INSTALLED_ADDRESS and the webapp would
   embed $EMBEDDED_ADDRESS. They would derive different addresses and the app
   would show an empty page with no error."
    [ "$INSTALLED_TIP" = "$EMBEDDED_TIP" ] || die \
      "the bridge would use tip contract $INSTALLED_TIP and the webapp would embed
   $EMBEDDED_TIP. Same failure."
    echo "  bridge and webapp agree on both contracts"
  fi

  # Re-run the bundle's own guards against the bytes just copied in. They are
  # the same checks CI runs; running them here catches a stale copy that CI,
  # which builds its own, cannot see.
  cargo test -p freenet-bitcoin-webapp --quiet keys::tests >/dev/null
  echo "  embedded-contract guards pass against these bytes"

  ( cd webapp && dx build --release >/dev/null )
  BUNDLE=target/dx/freenet-bitcoin-webapp/release/web/public
  # dx references style.css from index.html but does not copy it.
  cp webapp/assets/style.css "$BUNDLE/style.css"
  echo "  bundle at $BUNDLE"
  ls -la "$BUNDLE"

  # -------------------------------------------------------------------------
  step "Publish to the existing website contract"
  # -------------------------------------------------------------------------
  # `update`, never `publish`: the contract id is the app's URL and must not
  # move. `fdev website list` shows which id this key owns.
  run fdev website update --key "$WEBSITE_KEY" "$BUNDLE"
fi

step "Done"
if [ "$DRY_RUN" = 1 ]; then
  echo "  dry run: nothing was installed or published"
else
  echo "  bridge and webapp are on contract generation:"
  echo "    address $NEW_ADDRESS_HASH"
  echo "    tip     $NEW_TIP_HASH"
  echo
  echo "  Verify what a visitor sees, not what the logs say:"
  echo "    sudo -u btcbridge $BRIDGE_BIN --config $BRIDGE_CFG --print-generation"
  echo "    fdev website list"
fi
