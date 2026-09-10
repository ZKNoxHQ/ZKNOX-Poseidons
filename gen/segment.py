"""Segmentation of the statement list into small DAG segments."""
from yuldag import MODULUS

OPGAS = {"add": 3, "mulmod": 8, "addmod": 8}


def compute_order(dag, stmts):
    """Statement index at which each node is first materialized."""
    comp = {}
    for si, st in enumerate(stmts):
        if st[0] in ("let", "assign"):
            root = st[2]
        elif st[0] == "mstore":
            root = st[2]
        else:
            continue
        stack = [root]
        while stack:
            n = stack.pop()
            if n in comp:
                continue
            node = dag.nodes[n]
            if node.kind == "const":
                continue  # constants are pushed at use
            comp[n] = si
            stack.extend(node.args)
    return comp


def segments(dag, stmts, width, min_ops=1, max_ops=40, max_live=None, cut_ops=4, no_cut_before_sbox=False):
    """Split the statement list into segments at boundaries whose live set has
    at most `width` values. Returns list of (start_stmt, end_stmt, live_in, live_out)."""
    comp = compute_order(dag, stmts)
    final = [st for st in stmts if st[0] == "mstore"][0][2]
    n_st = len(stmts)
    # live after statement i: computed at <= i, has user computed > i (or final)
    last_use = {}
    for n, si in comp.items():
        node = dag.nodes[n]
        for u in node.users:
            if u in comp:
                last_use[n] = max(last_use.get(n, -1), comp[u])
    last_use[final] = n_st
    live_after = []
    for i in range(n_st):
        live = sorted(n for n, si in comp.items() if si <= i < last_use.get(n, -1))
        live_after.append(live)
    ops_at = [sum(1 for n, si in comp.items() if si == i and dag.nodes[n].kind in OPGAS) for i in range(n_st)]
    def starts_sbox(i):
        """statement i begins an S-box: its root is mulmod(x, x, F) or its first computed sub-node is"""
        if i >= n_st or stmts[i][0] not in ("let", "assign"):
            return False
        root = dag.nodes[stmts[i][2]]
        stack = [root]
        while stack:
            nd = stack.pop()
            if nd.kind == "mulmod":
                a, b = [x for x in nd.args if dag.nodes[x].kind != "const" or dag.nodes[x].val != dag.modulus]
                if a == b:
                    return True
            for a in nd.args:
                an = dag.nodes[a]
                if an.id in comp and comp[an.id] == i:
                    stack.append(an)
        return False

    def sbox_first_half(i):
        """statement i is `t := mulmod(x, x, F)`: never cut right after it"""
        if stmts[i][0] not in ("let", "assign"):
            return False
        nd = dag.nodes[stmts[i][2]]
        if nd.kind != "mulmod":
            return False
        a = [x for x in nd.args if not (dag.nodes[x].kind == "const" and dag.nodes[x].val == dag.modulus)]
        return len(a) == 2 and a[0] == a[1]

    def lone_sbox(i):
        """statement i starts an S-box that is not part of a full-round S-box layer"""
        return starts_sbox(i) and not starts_sbox(i + 2) and not (i >= 2 and starts_sbox(i - 2))

    # pass 1: natural cuts where the live set fits in the state width, except right
    # before a partial-round S-box (so F can be parked under its input by the linear layer)
    natural = [-1]
    ops_since = 0
    for i in range(n_st):
        ops_since += ops_at[i]
        if len(live_after[i]) <= width and (ops_since >= min_ops or i == n_st - 1) and \
                (i == n_st - 1 or not (no_cut_before_sbox and lone_sbox(i + 1))) and not sbox_first_half(i):
            natural.append(i)
            ops_since = 0
    # pass 2: blocks with more than `max_ops` op nodes are cut internally, never inside
    # an S-box nor right before one
    cuts = [-1]
    for a, b in zip(natural, natural[1:]):
        block_ops = sum(ops_at[a + 1:b + 1])
        if block_ops > max_ops and max_live is not None:
            ops_since = 0
            for i in range(a + 1, b):
                ops_since += ops_at[i]
                if len(live_after[i]) <= max_live and ops_since + ops_at[i + 1] > cut_ops and \
                        not sbox_first_half(i) and not (no_cut_before_sbox and lone_sbox(i + 1)):
                    cuts.append(i)
                    ops_since = 0
        cuts.append(b)
    segs = []
    for a, b in zip(cuts, cuts[1:]):
        live_in = live_after[a] if a >= 0 else []
        live_out = live_after[b]
        segs.append((a + 1, b, live_in, live_out))
    return segs, comp


