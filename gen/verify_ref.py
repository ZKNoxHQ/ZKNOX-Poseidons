"""Check gen/poseidon_ref.py against circomlibjs (constants, MDS, hash vectors) and hadeshash.

    python3 verify_ref.py ../test/circomlibjs_vectors.json
"""
import json
import sys

from poseidon_ref import PoseidonInstance, BN254, BLS12_381

vec = json.load(open(sys.argv[1]))
consts = json.load(open("../test/circomlib_constants.json"))
ok = True
for t, R_P in ((3, 57), (4, 56), (5, 60)):
    inst = PoseidonInstance(BN254, 254, t, 8, R_P)
    C = [int(x, 16) for x in consts[str(t)]["C"]]
    M = [[int(x, 16) for x in r] for r in consts[str(t)]["M"]]
    same = inst.round_constants == C and inst.mds == M
    ok &= same
    print(f"BN254 254/{t}/8/{R_P}: round constants and MDS == circomlib: {same}")
for t, key, R_P in ((3, "t3", 57), (4, "t4", 56)):
    inst = PoseidonInstance(BN254, 254, t, 8, R_P)
    bad = sum(inst.hash([int(x) for x in v["in"]]) != int(v["out"]) for v in vec[key])
    ok &= bad == 0
    print(f"BN254 t={t}: {len(vec[key])} circomlibjs hash vectors, mismatches = {bad}")
h = json.load(open("../params/poseidon_bls12381_255_5_8_60.json"))
inst = PoseidonInstance(BLS12_381, 255, 5, 8, 60)
same = [hex(c) for c in inst.round_constants] == h["round_constants"] and [[hex(x) for x in r] for r in inst.mds] == h["mds"]
ok &= same
print(f"BLS12-381 255/5/8/60: constants and MDS == params (hadeshash poseidonperm_x5_255_5): {same}")
for name in ("poseidon_bls12381_255_3_8_57",):
    j = json.load(open(f"../params/{name}.json"))
    inst = PoseidonInstance(int(j["p"], 16), j["n"], j["t"], j["R_F"], j["R_P"])
    perm = [hex(x) for x in inst.permutation(list(range(j["t"])))]
    same = perm == j["test_vectors"]["permutation(0..t-1)"]
    ok &= same
    print(f"{name}: permutation(0..t-1) == params: {same}")
sys.exit(0 if ok else 1)
