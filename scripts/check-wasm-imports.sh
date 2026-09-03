#!/usr/bin/env bash
# Fail if a contract imports anything the Freenet runtime does not register.
#
# Why this gate exists: Harvest published four WASM modules that could not
# instantiate at all, because a transitive dependency (chrono's default
# `wasmbind` feature) pulled in `__wbindgen_placeholder__` /
# `__wbindgen_externref_xform__`, which the runtime never registers. Nothing
# caught it -- the modules built fine, published fine, and simply failed to
# load. See freenet/harvest#8.
#
# The check is a set comparison over `wasm-objdump -j Import`, and it is cheap
# enough to run on every push.
set -euo pipefail

# Namespaces the runtime actually registers.
#
# DERIVED FROM freenet-core, NOT guessed. Regenerate with:
#
#   grep -rhoE '"freenet_[a-z_]+"' crates/core/src/ | sort -u
#
# Two false positives came from hand-writing this list: a delegate checked
# against the contract set, and then a delegate namespace simply missing. A
# gate that cries wolf gets switched off, so keep this derived.
#
# Contracts and delegates get DIFFERENT sets on purpose: a delegate may reach
# secret storage, the host RNG and its own context; a contract may not.
CONTRACT_NS="freenet_contract_io freenet_log freenet_time"
DELEGATE_NS="freenet_contract_io freenet_log freenet_time freenet_rand \
freenet_delegate_secrets freenet_delegate_ctx freenet_delegate_contracts \
freenet_delegate_management"

fail=0
for wasm in "$@"; do
  [ -f "$wasm" ] || { echo "missing: $wasm" >&2; fail=1; continue; }
  # Pick the allowlist by module kind. A delegate is identified by importing
  # the delegate-only secrets namespace.
  case "$(basename "$wasm")" in
    *delegate*) ALLOWED="$DELEGATE_NS"; kind=delegate ;;
    *)          ALLOWED="$CONTRACT_NS"; kind=contract ;;
  esac
  ns=$(wasm-objdump -j Import -x "$wasm" 2>/dev/null \
        | grep -oE "<- [A-Za-z_0-9]+" | sed 's/<- //' | sort -u)
  bad=""
  for n in $ns; do
    case " $ALLOWED " in
      *" $n "*) ;;
      *) bad="$bad $n" ;;
    esac
  done
  if [ -n "$bad" ]; then
    echo "FAIL [$kind] $(basename "$wasm") imports unregistered namespace(s):$bad" >&2
    echo "     this module cannot instantiate on a Freenet node" >&2
    fail=1
  else
    echo "ok   [$kind] $(basename "$wasm") imports: $(echo $ns | tr '\n' ' ')"
  fi
done
exit $fail
