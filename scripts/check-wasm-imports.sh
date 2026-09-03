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

# Namespaces the contract runtime actually provides.
ALLOWED="freenet_contract_io freenet_log freenet_time freenet_rand"

fail=0
for wasm in "$@"; do
  [ -f "$wasm" ] || { echo "missing: $wasm" >&2; fail=1; continue; }
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
    echo "FAIL $(basename "$wasm") imports unregistered namespace(s):$bad" >&2
    echo "     this module cannot instantiate on a Freenet node" >&2
    fail=1
  else
    echo "ok   $(basename "$wasm") imports: $(echo $ns | tr '\n' ' ')"
  fi
done
exit $fail
