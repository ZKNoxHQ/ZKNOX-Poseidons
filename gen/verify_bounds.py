"""Independent overflow check of the generated Yul: interval analysis on the parsed code.

Every `add` must be provably below 2^256 from the bounds of its operands alone:
a constant is itself, calldata is any 256-bit word, mulmod / addmod / mod results are below
their modulus.  This does not rely on the emitters' own bookkeeping.

    python3 verify_bounds.py ../yul/*.sol
"""
import sys

from yuldag import parse_library

CAP = (1 << 256) - 1


def check(path):
    dag, stmts = parse_library(path)
    bound = {}
    worst = 0
    n_add = 0
    for node in dag.nodes:                      # nodes are created operands first
        k = node.kind
        if k == "const":
            b = node.val
        elif k == "calldataload":
            b = CAP
        elif k in ("mulmod", "addmod"):
            m = dag.nodes[node.args[2]]
            assert m.kind == "const" and m.val > 0, "modulus must be a constant"
            b = m.val - 1
        elif k == "mod":
            m = dag.nodes[node.args[1]]
            assert m.kind == "const" and m.val > 0
            b = m.val - 1
        elif k == "add":
            b = bound[node.args[0]] + bound[node.args[1]]
            n_add += 1
            worst = max(worst, b)
            if b > CAP:
                return False, f"add may overflow (bound 2^256 * {b / (CAP + 1):.3f})", n_add
        else:
            raise ValueError(f"unexpected operation {k}")
        bound[node.id] = b
    return True, f"largest add bound = 2^256 * {worst / (CAP + 1):.4f}", n_add


if __name__ == "__main__":
    ok = True
    for path in sys.argv[1:]:
        good, msg, n_add = check(path)
        ok &= good
        print(f"{'ok  ' if good else 'FAIL'} {path.split('/')[-1]:34s} {n_add:4d} add, {msg}")
    sys.exit(0 if ok else 1)
