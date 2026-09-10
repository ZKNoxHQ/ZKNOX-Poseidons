"""Replay edge, unreduced and random inputs through the BLS12-381 runtimes in the mini EVM.

    python3 verify_bls.py ../artifacts/bls12-381
"""
import random
import sys

from build import run, selector_of
from poseidon_ref import PoseidonInstance, BLS12_381

art = sys.argv[1]
p = BLS12_381
ok = True
for w, name, R_P in ((3, "PoseidonT3BLS12381", 57), (4, "PoseidonT4BLS12381", 56)):
    inst = PoseidonInstance(p, 255, w, 8, R_P)
    code = bytes.fromhex(open(f"{art}/{name}.runtime.hex").read().strip()[2:])
    sel = selector_of(f"poseidon(bytes32[{w - 1}])").to_bytes(4, "big")
    rnd = random.Random(7)
    n = w - 1
    vecs = [list(range(1, w)), [0] * n, [p - 1] * n, [p] * n, [2 ** 256 - 1] * n, [2 ** 255] * n, [p + 1] * n] + \
        [[rnd.getrandbits(256) for _ in range(n)] for _ in range(400)]
    bad, gases = 0, set()
    for v in vecs:
        out, gas = run(code, sel + b"".join(x.to_bytes(32, "big") for x in v))
        gases.add(gas)
        bad += int.from_bytes(out, "big") != inst.hash(v)
    rej = run(code, b"\xde\xad\xbe\xef" + b"\0" * 32 * n)[0] is None and run(code, sel + b"\0" * (32 * n - 8))[0] is None
    ok &= bad == 0 and rej
    print(f"{name} 255/{w}/8/{R_P}: {len(vecs)} vectors, mismatches={bad}, gas={sorted(gases)}, runtime={len(code)} bytes, rejects bad calls={rej}")
sys.exit(0 if ok else 1)
