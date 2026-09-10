"""Stack scheduler for small straight-line EVM segments.

Segment model
-------------
kinds[i] in {'input','const','calldataload','mulmod','addmod','sum'}.
  * mulmod/addmod: args = (a, b); the modulus F (id -1) must sit directly below a and b.
  * sum: args = tuple of terms, computed as any binary tree of ADDs.
A stack slot holds a node id (complete value), F, or ('S', sum_id, mask) for a
partial sum.  Inputs are numbered 0..k-1 in stack order (deepest first) and
the segment must end with exactly its outputs above F.

Search
------
Macro moves: for every ready op the preparatory shuffle is built from a few
canonical patterns (SWAP consumed operands to the top, insert F with DUPF and
SWAP1/SWAP2 or reuse one already in place, DUP/PUSH operands that keep further
uses, optionally park an extra F under the result), then the op fires.
Dijkstra / weighted A* runs over the states reached right after an op.
Costs: PUSHn 3, DUPn 3, SWAPn 3, ADD 3, MULMOD/ADDMOD 8, CALLDATALOAD 3+3.
"""
import heapq
import itertools
from collections import deque

OPGAS = {"mulmod": 8, "addmod": 8, "add": 3}
PUSH_COST = {"const": 3, "calldataload": 6}
F = -1


def _stack_stats(stack):
    cnt = {}
    parts = {}
    for v in stack:
        cnt[v] = cnt.get(v, 0) + 1
        if type(v) is tuple:
            parts.setdefault(v[1], []).append(v[2])
    return cnt, parts


class Seg:
    def __init__(self, kinds, args, inputs, outputs):
        self.kinds = list(kinds)
        self.args = [tuple(a) for a in args]
        self.inputs = tuple(inputs)
        self.outputs = tuple(outputs)
        self.n = len(kinds)
        self.ops = [i for i, k in enumerate(self.kinds) if k in ("mulmod", "addmod", "sum")]
        self.opbit = {o: 1 << j for j, o in enumerate(self.ops)}
        self.all_done = (1 << len(self.ops)) - 1
        # consumers of each value: list of op ids (one per operand slot)
        self.users = [[] for _ in range(self.n)]
        for o in self.ops:
            for a in self.args[o]:
                self.users[a].append(o)
        self.is_out = [0] * self.n
        for o in self.outputs:
            self.is_out[o] += 1
        self.term_bit = {}
        for o in self.ops:
            if self.kinds[o] == "sum":
                self.term_bit[o] = {t: 1 << j for j, t in enumerate(self.args[o])}
        self.pushable = [k in PUSH_COST for k in self.kinds]
        self.key = (tuple(self.kinds), tuple(self.args), self.inputs, self.outputs)




class Solver:
    def __init__(self, seg, max_prep=None, max_prep_moves=None):
        self.seg = seg
        s = seg
        self.full_mask = {o: (1 << len(s.args[o])) - 1 for o in s.ops if s.kinds[o] == "sum"}
        self.modops = [o for o in s.ops if s.kinds[o] != "sum"]
        self.sums = [o for o in s.ops if s.kinds[o] == "sum"]

    def uses_left(self, v, done, parts):
        s = self.seg
        n = s.is_out[v]
        for u in s.users[v]:
            if done & s.opbit[u]:
                continue
            if s.kinds[u] == "sum":
                b = s.term_bit[u][v]
                if any(m & b for m in parts.get(u, ())):
                    continue
            n += 1
        return n

    def heuristic(self, stack, done):
        s = self.seg
        cnt, parts = _stack_stats(stack)
        h = 0
        modleft = 0
        for o in s.ops:
            if done & s.opbit[o]:
                continue
            if s.kinds[o] == "sum":
                adds = len(s.args[o]) - 1 - sum(bin(m).count("1") - 1 for m in parts.get(o, ()))
                h += 3 * adds
            else:
                h += 8
                modleft += 1
        h += 3 * max(0, modleft - cnt.get(F, 0))
        for v in range(s.n):
            k = s.kinds[v]
            if s.pushable[v]:
                h += PUSH_COST[k] * max(0, self.uses_left(v, done, parts) - cnt.get(v, 0))
            elif k == "input" or done & s.opbit.get(v, 0):
                h += 3 * max(0, self.uses_left(v, done, parts) - cnt.get(v, 0))
            elif k in ("mulmod", "addmod", "sum"):
                h += 3 * max(0, self.uses_left(v, done, parts) - 1)
        return h

    # ---- pattern-based prep ------------------------------------------------
    def preps(self, stack, done, x, y, needF):
        """Return {stack_after_prep: (cost, prog)} for canonical prep sequences
        after which op(x, y) can fire."""
        s = self.seg
        cnt, parts = _stack_stats(stack)

        def depth(st, v, skip=0):
            k = 0
            for i in range(1, len(st) + 1):
                if st[-i] == v:
                    if k == skip:
                        return i
                    k += 1
            return None

        def is_const(v):
            return type(v) is not tuple and s.pushable[v]

        def uses(v):
            return 1 if type(v) is tuple else self.uses_left(v, done, parts)

        if x == y:
            c, u = cnt.get(x, 0), uses(x)
            role_sets = []
            if c >= 1 and u == c + 1:
                role_sets.append(("consume", "copy"))
            if c >= 1 and u >= c + 2:
                role_sets.append(("copy", "copy"))
            if c >= 2 and u == c:
                role_sets.append(("consume", "consume"))
        else:
            opts = []
            for v in (x, y):
                r = []
                if is_const(v):
                    r.append("copy")
                else:
                    c, u = cnt.get(v, 0), uses(v)
                    if c > 0 and c == u:
                        r.append("consume")
                    if c > 0 and c < u:
                        r.append("copy")
                opts.append(r)
            role_sets = [(rx, ry) for rx in opts[0] for ry in opts[1]]
        results = {}
        modleft = sum(1 for o in self.modops if not done & s.opbit[o])

        def simulate(prog):
            st = list(stack)
            cost = 0
            fc = cnt.get(F, 0)
            for mv in prog:
                if mv[0] == "DUPF":
                    if len(st) > 15 or fc >= modleft:
                        return None
                    st.append(F)
                    fc += 1
                    cost += 3
                elif mv[0] == "PUSH":
                    st.append(mv[1])
                    cost += PUSH_COST[s.kinds[mv[1]]]
                elif mv[0] == "DUP":
                    if mv[1] > 16 or mv[1] > len(st):
                        return None
                    st.append(st[-mv[1]])
                    cost += 3
                elif mv[0] == "SWAP":
                    n = mv[1]
                    if n > 16 or n >= len(st):
                        return None
                    st[-1], st[-1 - n] = st[-1 - n], st[-1]
                    cost += 3
            return cost, tuple(st)

        def fires(st):
            if len(st) < 2:
                return False
            t, t2 = st[-1], st[-2]
            if not ((t, t2) == (x, y) or (t, t2) == (y, x)):
                return False
            return (len(st) >= 3 and st[-3] == F) if needF else True

        def add(prog):
            r = simulate(prog)
            if r is None:
                return
            cost, st = r
            if fires(st) and (st not in results or results[st][0] > cost):
                results[st] = (cost, tuple(prog))

        for roles in role_sets:
            consumed = [v for v, r in zip((x, y), roles) if r == "consume"]
            copied = [v for v, r in zip((x, y), roles) if r == "copy"]
            prefixes = []
            if len(consumed) == 0:
                prefixes.append([])
            elif len(consumed) == 1:
                d = depth(stack, consumed[0])
                prefixes.append([] if d == 1 else [("SWAP", d - 1)])
            else:
                c1, c2 = consumed
                d1 = depth(stack, c1)
                d2 = depth(stack, c2, skip=1) if x == y else depth(stack, c2)
                if {d1, d2} == {1, 2}:
                    prefixes.append([])
                else:
                    for dt, do in ((d1, d2), (d2, d1)):
                        if dt == 1:
                            prefixes.append([("SWAP", 1), ("SWAP", do - 1)])
                        else:
                            pre = [("SWAP", dt - 1)]
                            # after the swap, the other operand is at depth `do` unless it was on top
                            do2 = dt if do == 1 else do
                            if do2 == 2:
                                prefixes.append(pre)
                            else:
                                prefixes.append(pre + [("SWAP", 1), ("SWAP", do2 - 1)])
            for pre in prefixes:
                r = simulate(pre)
                if r is None:
                    continue
                st1 = r[1]
                k = len(consumed)
                mids = []
                if needF:
                    if k == 0:
                        mids.append([("DUPF",)])
                        mids.append([("DUPF",), ("DUPF",)])          # park an F under the result
                        if st1 and st1[-1] == F:
                            mids.append([])
                    elif k == 1:
                        mids.append([("DUPF",), ("SWAP", 1)])
                        mids.append([("DUPF",), ("DUPF",), ("SWAP", 2)])
                        if len(st1) >= 2 and st1[-2] == F:
                            mids.append([])
                    else:
                        mids.append([("DUPF",), ("SWAP", 2)])
                        if len(st1) >= 3 and st1[-3] == F:
                            mids.append([])
                else:
                    mids.append([])
                    if k == 0:
                        mids.append([("DUPF",)])
                    elif k == 1:
                        mids.append([("DUPF",), ("SWAP", 1)])
                    else:
                        mids.append([("DUPF",), ("SWAP", 2)])
                for mid in mids:
                    r2 = simulate(pre + mid)
                    if r2 is None:
                        continue
                    _, st2 = r2
                    orders = [copied] if len(copied) < 2 else [copied, copied[::-1]]
                    for order in orders:
                        prog = list(pre) + list(mid)
                        stc = list(st2)
                        ok = True
                        for v in order:
                            if is_const(v):
                                prog.append(("PUSH", v))
                                stc.append(v)
                            else:
                                d = depth(tuple(stc), v)
                                if d is None or d > 16:
                                    ok = False
                                    break
                                prog.append(("DUP", d))
                                stc.append(v)
                        if ok:
                            add(prog)
        return results

    def successors(self, stack, done):
        s = self.seg
        cnt, parts = _stack_stats(stack)
        out = []

        def avail(v):
            return s.pushable[v] or cnt.get(v, 0) > 0

        for o in self.modops:
            if done & s.opbit[o]:
                continue
            a, b = s.args[o]
            if not (avail(a) and avail(b)):
                continue
            for st, (c, prog) in self.preps(stack, done, a, b, True).items():
                out.append((c + 8, st[:-3] + (o,), done | s.opbit[o], prog + (("OP", s.kinds[o], o),)))
        for o in self.sums:
            if done & s.opbit[o]:
                continue
            partial = [("S", o, m) for m in parts.get(o, ())]
            terms = []
            for t in s.args[o]:
                if any(m & s.term_bit[o][t] for m in parts.get(o, ())):
                    continue
                if avail(t):
                    terms.append(t)
            # at most one partial sum per sum node: grow it one term at a time
            if partial:
                pairs = [(partial[0], t) for t in terms]
            else:
                pairs = [(terms[i], terms[j]) for i in range(len(terms)) for j in range(i + 1, len(terms))]
            for p, q in pairs:
                if True:
                    mp = p[2] if type(p) is tuple else s.term_bit[o][p]
                    mq = q[2] if type(q) is tuple else s.term_bit[o][q]
                    m = mp | mq
                    for st, (c, prog) in self.preps(stack, done, p, q, False).items():
                        if m == self.full_mask[o]:
                            out.append((c + 3, st[:-2] + (o,), done | s.opbit[o], prog + (("OP", "add", o),)))
                        else:
                            out.append((c + 3, st[:-2] + (("S", o, m),), done, prog + (("OP", "add", o),)))
        return out

    def finish(self, stack, target):
        if stack == target:
            return 0, ()
        seen = {stack}
        dq = deque([(stack, 0, ())])
        while dq:
            st, c, prog = dq.popleft()
            for n in range(1, len(st)):
                ns = list(st)
                ns[-1], ns[-1 - n] = ns[-1 - n], ns[-1]
                ns = tuple(ns)
                if ns == target:
                    return c + 3, prog + (("SWAP", n),)
                if ns not in seen:
                    seen.add(ns)
                    dq.append((ns, c + 3, prog + (("SWAP", n),)))
        return None

    def solve(self, slack=0, want_all_orders=True, max_expand=300000, weight=1.0, extra_swaps=1):
        """Dijkstra / weighted A* over post-op states.  Returns {output_order: (cost, program)}
        for the output orders that arise naturally (the final stack of a goal state, plus
        every order reachable from it with `extra_swaps` SWAPs); orders more than
        `slack` above the cheapest are dropped."""
        s = self.seg
        W = weight
        start = (s.inputs, 0)
        best = {start: 0}
        parent = {start: None}
        pq = [(W * self.heuristic(*start), 0, 0, start)]
        tie = 1
        found = {}
        best_goal = None
        expanded = 0
        outset = set(s.outputs)
        while pq:
            f, g, _, st = heapq.heappop(pq)
            if best.get(st, 1 << 60) < g:
                continue
            if best_goal is not None and g > best_goal + slack + 3 * extra_swaps:
                break
            stack, done = st
            if done == s.all_done:
                if set(stack) != outset or len(stack) != len(s.outputs):
                    continue
                base = []
                cur = st
                while parent[cur] is not None:
                    prev, mv = parent[cur]
                    base.extend(reversed(mv))
                    cur = prev
                base.reverse()
                variants = [(stack, 0, ())]
                frontier = [(stack, ())]
                for _ in range(extra_swaps):
                    nxt = []
                    for stk, prog in frontier:
                        for n in range(1, len(stk)):
                            ns = list(stk)
                            ns[-1], ns[-1 - n] = ns[-1 - n], ns[-1]
                            ns = tuple(ns)
                            variants.append((ns, 3 * (len(prog) + 1), prog + (("SWAP", n),)))
                            nxt.append((ns, prog + (("SWAP", n),)))
                    frontier = nxt
                for order, c, prog in variants:
                    if order not in found or found[order][0] > g + c:
                        found[order] = (g + c, base + list(prog))
                if best_goal is None or g < best_goal:
                    best_goal = g
                continue
            expanded += 1
            if expanded > max_expand:
                break
            for c, nstack, ndone, prog in self.successors(stack, done):
                ns = (nstack, ndone)
                ng = g + c
                if ng < best.get(ns, 1 << 60):
                    best[ns] = ng
                    parent[ns] = (st, prog)
                    heapq.heappush(pq, (ng + W * self.heuristic(nstack, ndone), ng, tie, ns))
                    tie += 1
        if best_goal is not None:
            found = {k: v for k, v in found.items() if v[0] <= best_goal + slack + 3 * extra_swaps}
        return found, expanded
