"""Canonical form of a segment (constants abstracted, sums flattened)."""
from yuldag import MODULUS
from sched import Seg, F

class Canon:
    """Canonical segment with flattened sums."""
    def __init__(self, dag, comp, seg, in_order, out_order):
        s0, s1, _, _ = seg
        self.kinds, self.args, self.actual = [], [], []
        self.idmap = {}
        for n in in_order:
            self.idmap[n] = len(self.kinds); self.kinds.append("input"); self.args.append(()); self.actual.append(n)
        in_set = set(in_order)

        def new(kind, args, actual):
            cid = len(self.kinds); self.kinds.append(kind); self.args.append(tuple(args)); self.actual.append(actual); return cid

        def terms_of(n):
            """flatten an add tree rooted at n into leaf node ids"""
            node = dag.nodes[n]
            out = []
            for a in node.args:
                an = dag.nodes[a]
                if an.kind == "add" and len(an.users) == 1 and a not in in_set:
                    out.extend(terms_of(a))
                else:
                    out.append(a)
            return out

        def visit(n):
            node = dag.nodes[n]
            if node.kind == "const":
                if node.val == dag.modulus: return F
                return new("const", (), n)
            if n in in_set or n in self.idmap: return self.idmap[n]
            if node.kind == "calldataload":
                self.idmap[n] = new("calldataload", (), n); return self.idmap[n]
            assert s0 <= comp[n] <= s1, (n, comp[n], s0, s1)
            if node.kind == "add":
                ts = [visit(t) for t in terms_of(n)]
                assert F not in ts
                self.idmap[n] = new("sum", ts, n); return self.idmap[n]
            ca = [c for c in (visit(a) for a in node.args) if c != F]
            assert node.kind in ("mulmod", "addmod"), node.kind
            self.idmap[n] = new(node.kind, ca, n); return self.idmap[n]

        self.outputs = [visit(n) for n in out_order]
        self.inputs = list(range(len(in_order)))
        self.seg = Seg(self.kinds, self.args, self.inputs, self.outputs)
