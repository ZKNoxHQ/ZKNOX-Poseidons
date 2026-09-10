"""Benchmark iden3 (the shielded pool's deployed bytecode), the poseidon-solidity fork, and the
generated runtimes on a local anvil: single hash (cold/warm STATICCALL) and the shielded pool's
Commitments.insertLeaves.  Run from the bench/ directory with anvil listening on :8545.

    anvil --silent --gas-limit 400000000 --code-size-limit 100000 &
    python3 run_bench.py
"""
import argparse
import json
import os
import random
import sys
import time
import urllib.request

from Crypto.Hash import keccak

ap = argparse.ArgumentParser(description="Poseidon gas benchmark on a local anvil")
ap.add_argument("--check", metavar="EXPECTED_JSON", help="compare the measurements with this file, exit 1 on any deviation")
ap.add_argument("--write", metavar="EXPECTED_JSON", help="write the measurements as the new expected values")
args = ap.parse_args()

RPC = "http://127.0.0.1:8545"
FROM = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
_id = [0]


def rpc(method, params):
    _id[0] += 1
    req = urllib.request.Request(
        RPC, data=json.dumps({"jsonrpc": "2.0", "id": _id[0], "method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json"})
    r = json.load(urllib.request.urlopen(req))
    if "error" in r:
        raise RuntimeError(f"{method}: {r['error']}")
    return r["result"]


def deploy(bytecode):
    if not bytecode.startswith("0x"):
        bytecode = "0x" + bytecode
    tx = rpc("eth_sendTransaction", [{"from": FROM, "data": bytecode.strip(), "gas": hex(150_000_000)}])
    rec = None
    for _ in range(200):
        rec = rpc("eth_getTransactionReceipt", [tx])
        if rec:
            break
        time.sleep(0.05)
    assert rec and rec["status"] == "0x1", ("deploy failed", rec)
    return rec["contractAddress"], int(rec["gasUsed"], 16)


def call(to, data):
    return rpc("eth_call", [{"from": FROM, "to": to, "data": data, "gas": hex(150_000_000)}, "latest"])


def selector(sig):
    h = keccak.new(digest_bits=256)
    h.update(sig.encode())
    return "0x" + h.hexdigest()[:8]


def artifact(p):
    return json.load(open(p))["bytecode"]["object"]


def w(x):
    return "%064x" % (x % (1 << 256))


libs = {}
sources = [
    ("iden3_T3", open(f"{HERE}/gen/iden3_T3.hex").read().strip(), "poseidon(bytes32[2])"),
    ("fork_T3", artifact(f"{ROOT}/out/RefPoseidonT3.sol/RefPoseidonT3.json"), "hash(uint256[2])"),
    ("new_T3", open(f"{ROOT}/artifacts/PoseidonT3.creation.hex").read().strip(), "poseidon(bytes32[2])"),
    ("iden3_T4", open(f"{HERE}/gen/iden3_T4.hex").read().strip(), "poseidon(bytes32[3])"),
    ("fork_T4", artifact(f"{ROOT}/out/RefPoseidonT4.sol/RefPoseidonT4.json"), "hash(uint256[3])"),
    ("new_T4", open(f"{ROOT}/artifacts/PoseidonT4.creation.hex").read().strip(), "poseidon(bytes32[3])"),
    # BLS12-381 scalar field: solc-compiled generated Yul (reference) and the scheduled bytecode
    ("yul_T3_bls", artifact(f"{ROOT}/out/RefPoseidonT3BLS.sol/RefPoseidonT3BLS.json"), "hash(uint256[2])"),
    ("new_T3_bls", open(f"{ROOT}/artifacts/bls12-381/PoseidonT3BLS12381.creation.hex").read().strip(), "poseidon(bytes32[2])"),
    ("yul_T4_bls", artifact(f"{ROOT}/out/RefPoseidonT4BLS.sol/RefPoseidonT4BLS.json"), "hash(uint256[3])"),
    ("new_T4_bls", open(f"{ROOT}/artifacts/bls12-381/PoseidonT4BLS12381.creation.hex").read().strip(), "poseidon(bytes32[3])"),
    # platus-xyz/poseidon2-solidity: Poseidon2 (t=4 sponge, rate 3) over BN254, selector-less packed calldata
    ("platus_p2", open(f"{HERE}/gen/platus_poseidon2_bn254.hex").read().strip(), None),
]
print("== deploying ==")
SEL = {}
for name, src, sig in sources:
    if not os.path.exists(src) and src.startswith("0x") is False and len(src) < 200:
        continue
    addr, gas = deploy(src)
    size = (len(rpc("eth_getCode", [addr, "latest"])) - 2) // 2
    libs[name] = {"addr": addr, "deploy_gas": gas, "size": size}
    SEL[name] = selector(sig) if sig else "0x"
    print(f"  {name:9s} {addr}  runtime={size:>6,} B  deployGas={gas:>9,}")

print("\n== functional equivalence ==")
random.seed(1)
for arity, group in ((2, ["iden3_T3", "fork_T3", "new_T3"]), (3, ["iden3_T4", "fork_T4", "new_T4"]),
                     (2, ["yul_T3_bls", "new_T3_bls"]), (3, ["yul_T4_bls", "new_T4_bls"])):
    group = [g for g in group if g in libs]
    vectors = [[1, 2, 3][:arity], [0] * arity, [P - 1] * arity, [P] * arity, [(1 << 256) - 1] * arity] + \
              [[random.getrandbits(256) for _ in range(arity)] for _ in range(300)]
    mism = 0
    for v in vectors:
        outs = {call(libs[nm]["addr"], SEL[nm] + "".join(w(x) for x in v)) for nm in group}
        if len(outs) != 1:
            mism += 1
            if mism < 3:
                print("   MISMATCH", v)
    print(f"  T{arity + 1}: {len(vectors)} vectors across {group}: mismatches = {mism}")

print("\n== single hash via STATICCALL (cold = first touch of the library account, warm = second call) ==")
sh_addr, _ = deploy(artifact(f"{HERE}/out/Bench.sol/SingleHash.json"))
run_sel = selector("run(address,bytes)")
single = {}
for arity, group in ((2, ["iden3_T3", "fork_T3", "new_T3", "yul_T3_bls", "new_T3_bls"]),
                     (3, ["iden3_T4", "fork_T4", "new_T4", "yul_T4_bls", "new_T4_bls"])):
    for nm in group:
        if nm not in libs:
            continue
        inner = bytes.fromhex((SEL[nm] + "".join(w(x) for x in range(1, arity + 1)))[2:])
        data = run_sel + w(int(libs[nm]["addr"], 16)) + w(0x40) + w(len(inner)) + \
            inner.hex().ljust(((len(inner) + 31) // 32) * 64, "0")
        res = call(sh_addr, data)[2:]
        cold, warm = int(res[0:64], 16), int(res[64:128], 16)
        single[nm] = (cold, warm)
        print(f"  {nm:9s} cold={cold:>7,}  warm={warm:>7,}")
    if "platus_p2" in libs:
        nm = f"platus_p2_{arity}w"
        inner = bytes.fromhex("".join(w(x) for x in range(1, arity + 1)))
        data = run_sel + w(int(libs["platus_p2"]["addr"], 16)) + w(0x40) + w(len(inner)) + \
            inner.hex().ljust(((len(inner) + 31) // 32) * 64, "0")
        res = call(sh_addr, data)[2:]
        cold, warm = int(res[0:64], 16), int(res[64:128], 16)
        single[nm] = (cold, warm)
        print(f"  {nm:9s} cold={cold:>7,}  warm={warm:>7,}   (Poseidon2 t=4 sponge, {arity} packed words)")

print("\n== the shielded pool Commitments.insertLeaves (TREE_DEPTH=16, PoseidonT3) ==")
cb = artifact(f"{HERE}/out/CommitmentsBench.sol/CommitmentsBench.json")
measure_sel = selector("measure(uint256)")
il = {}
for nm in ["iden3_T3", "fork_T3", "new_T3", "yul_T3_bls", "new_T3_bls"]:
    if nm not in libs:
        continue
    addr, _ = deploy(cb + w(int(libs[nm]["addr"], 16)) + SEL[nm][2:].ljust(64, "0"))
    row = {}
    roots = {}
    for n in (1, 2, 4, 8):
        res = call(addr, measure_sel + w(n))[2:]
        row[n] = int(res[:64], 16)
        roots[n] = res[64:128]
    il[nm] = (row, roots)
    print(f"  {nm:9s} " + "  ".join(f"{n}leaf={row[n]:>8,}" for n in (1, 2, 4, 8)))
if "platus_p2" in libs:
    cbp = artifact(f"{HERE}/out/CommitmentsBenchPacked.sol/CommitmentsBenchPacked.json")
    addr, _ = deploy(cbp + w(int(libs["platus_p2"]["addr"], 16)))
    row, roots = {}, {}
    for n in (1, 2, 4, 8):
        res = call(addr, measure_sel + w(n))[2:]
        row[n] = int(res[:64], 16)
        roots[n] = res[64:128]
    il["platus_p2"] = (row, roots)
    print(f"  {'platus_p2':9s} " + "  ".join(f"{n}leaf={row[n]:>8,}" for n in (1, 2, 4, 8)) + "   (Poseidon2, own roots)")
if "new_T3" in il and "iden3_T3" in il:
    assert il["new_T3"][1] == il["iden3_T3"][1], "Merkle roots differ!"
    assert il["new_T3_bls"][1] == il["yul_T3_bls"][1], "BLS Merkle roots differ!"
    print("  roots identical within each field")
    for n in (1, 2, 4, 8):
        a, b = il["iden3_T3"][0][n], il["new_T3"][0][n]
        f = il["fork_T3"][0][n] if "fork_T3" in il else None
        print(f"  insertLeaves({n}): iden3={a:,}  fork={f:,}  new={b:,}  saved vs iden3={a - b:,} ({100 * (a - b) / a:.1f}%)"
              + (f"  vs fork={f - b:,} ({100 * (f - b) / f:.1f}%)" if f else ""))

results = {"single": {k: {"cold": v[0], "warm": v[1]} for k, v in single.items()},
           "insertLeaves": {k: {str(n): g for n, g in v[0].items()} for k, v in il.items()},
           "runtime_bytes": {k: v["size"] for k, v in libs.items()}}
json.dump({"libs": libs, **results}, open(f"{HERE}/bench_results.json", "w"), indent=2)
print("\nwritten bench_results.json")

if args.write:
    json.dump(results, open(args.write, "w"), indent=2)
    print(f"expected values written to {args.write}")
if args.check:
    expected = json.load(open(args.check))
    print(f"\n== check against {os.path.basename(args.check)} ==")
    bad = 0
    rows = []
    for section in ("single", "insertLeaves", "runtime_bytes"):
        for name, exp in expected.get(section, {}).items():
            got = results[section].get(name)
            if isinstance(exp, dict):
                for k, ev in exp.items():
                    gv = None if got is None else got.get(k)
                    ok = gv == ev
                    bad += not ok
                    rows.append((f"{section}.{name}.{k}", ev, gv, ok))
            else:
                ok = got == exp
                bad += not ok
                rows.append((f"{section}.{name}", exp, got, ok))
    w = max(len(r[0]) for r in rows)
    for label, ev, gv, ok in rows:
        print(f"  {label:{w}s}  expected {ev:>9,}  measured {gv if gv is None else format(gv, ',')!s:>9}  {'ok' if ok else 'DEVIATION'}")
    print(f"  {len(rows) - bad}/{len(rows)} measurements confirmed")
    if bad:
        sys.exit(1)
