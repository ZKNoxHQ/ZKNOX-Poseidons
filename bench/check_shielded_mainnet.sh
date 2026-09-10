#!/usr/bin/env bash
# Verify which Poseidon bytecode the shielded pool's mainnet contract actually links to.
#
#   RPC=https://ethereum-rpc.publicnode.com bench/check_shielded_mainnet.sh
#
# 1. reads the implementation behind the shielded pool proxy (EIP-1967 slot),
# 2. extracts every PUSH20 constant of the implementation (library addresses are linked that way),
# 3. fetches the code of each candidate and matches it against the known runtimes:
#    circomlibjs createCode(2|3) (bench/gen/iden3_T*.hex, runtime = suffix of the creation code),
#    poseidon-solidity and this repo's artifacts.
# Requires Foundry's `cast` and python3.
set -euo pipefail
RPC="${RPC:-${ETH_RPC_URL:-}}"
[ -n "$RPC" ] || { echo "set RPC=<mainnet json-rpc url>"; exit 2; }
PROXY=0xFA7093CDD9EE6932B4eb2c9e1cde7CE00B1FA4b9   # @shielded-community/deployments, ethereum.proxy
SLOT=0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc   # eip1967.proxy.implementation
cd "$(dirname "$0")/.."
IMPL=0x$(cast storage "$PROXY" "$SLOT" --rpc-url "$RPC" | tail -c 41)
echo "proxy          $PROXY"
echo "implementation $IMPL"
IMPLCODE=$(cast code "$IMPL" --rpc-url "$RPC")
echo "implementation code: $(( (${#IMPLCODE} - 2) / 2 )) bytes"
python3 - "$IMPLCODE" "$RPC" <<'PY'
import re, subprocess, sys
code, rpc = sys.argv[1][2:].lower(), sys.argv[2]
sel_t3, sel_t4 = "299e5660", "5a53025d"          # poseidon(bytes32[2]), poseidon(bytes32[3])
known = {}
for label, path, kind in (("circomlibjs createCode(2) [iden3 T3]", "bench/gen/iden3_T3.hex", "creation"),
                          ("circomlibjs createCode(3) [iden3 T4]", "bench/gen/iden3_T4.hex", "creation"),
                          ("this repo PoseidonT3 (BN254)", "artifacts/PoseidonT3.runtime.hex", "runtime"),
                          ("this repo PoseidonT4 (BN254)", "artifacts/PoseidonT4.runtime.hex", "runtime")):
    known[label] = (open(path).read().strip().lower().removeprefix("0x"), kind)
cands = sorted(set(re.findall(r"73([0-9a-f]{40})", code)))
print(f"{len(cands)} PUSH20 constants in the implementation")
found = 0
for a in cands:
    addr = "0x" + a
    c = subprocess.run(["cast", "code", addr, "--rpc-url", rpc], capture_output=True, text=True).stdout.strip().lower().removeprefix("0x")
    if len(c) < 2000:          # not a hash library (EOA, small contract)
        continue
    sels = [s for s in (sel_t3, sel_t4) if s in c]
    match = [lbl for lbl, (h, kind) in known.items() if (h.endswith(c) if kind == "creation" else h == c)]
    print(f"  {addr}: {len(c)//2:6d} bytes, selectors {sels or '-'}, matches {match or 'NONE of the known runtimes'}")
    found += bool(match)
print("verdict:", "the shielded pool links circomlibjs (iden3) Poseidon bytecode" if found else "no known runtime matched; inspect the candidates above")
PY
