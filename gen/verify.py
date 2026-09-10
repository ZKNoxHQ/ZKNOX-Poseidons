"""Replay circomlibjs vectors (test/circomlibjs_vectors.json) through the generated runtimes
in the mini EVM:  python3 gen/verify.py artifacts test/circomlibjs_vectors.json"""
import json
import sys

from build import run, selector_of

art, vec = sys.argv[1], json.load(open(sys.argv[2]))
for name, key, w in (("PoseidonT3", "t3", 3), ("PoseidonT4", "t4", 4)):
    code = bytes.fromhex(open(f"{art}/{name}.runtime.hex").read().strip()[2:])
    sig = json.load(open(f"{art}/{name}.json"))["signatures"][0]
    sel = selector_of(sig).to_bytes(4, "big")
    bad, gases = 0, set()
    for v in vec[key]:
        out, gas = run(code, sel + b"".join(int(x).to_bytes(32, "big") for x in v["in"]))
        gases.add(gas)
        bad += int.from_bytes(out, "big") != int(v["out"])
    print(f"{name} {sig}: {len(vec[key])} vectors, mismatches={bad}, gas={sorted(gases)}, runtime={len(code)} bytes")
