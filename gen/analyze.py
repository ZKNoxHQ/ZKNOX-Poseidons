"""Per-structure cost breakdown of a planned schedule (uses the memo checkpoint)."""
import sys, collections
from yuldag import parse_library
from build import plan
path, width, memo = sys.argv[1], int(sys.argv[2]), sys.argv[3]
kw = dict(weight=float(sys.argv[4]), max_expand=int(sys.argv[5]), keep=int(sys.argv[6]), slack=int(sys.argv[7]),
          block_max=int(sys.argv[8]), max_live=int(sys.argv[9]))
dag, stmts = parse_library(path)
chain, total = plan(dag, stmts, width, memo_path=memo, verbose=False, **kw)
print("body gas", total)
c = collections.Counter(); cost = collections.Counter(); ex = {}
for cn, co, prog, cst in chain:
    ops = tuple(k for k in cn.kinds if k not in ('input', 'const', 'calldataload'))
    key = (len(cn.inputs), len(cn.outputs), ops)
    c[key] += 1; cost[key] += cst
    ex.setdefault(key, []).append((cst, prog))
for k in c:
    swaps = min(sum(1 for i in e[1] if i[0] == 'SWAP') for e in ex[k])
    print(f"{c[k]:3d} x {cost[k]/c[k]:7.1f} gas  min {min(e[0] for e in ex[k])}  swaps(min) {swaps}  {k[0]}->{k[1]} {k[2]}")
