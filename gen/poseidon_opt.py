"""From a reference Poseidon instance to the optimised circuit and its Yul body.

Pipeline
--------
1. `optimize(inst)`: fold the partial-round constants into lane 0, factor the partial-round
   linear layers into sparse matrices (pre-sparse matrix P before the partial rounds), fold
   the first round's constant S-box of lane 0 (capacity = 0) and keep only row 0 of the last
   round.  Checked against the reference permutation with exact arithmetic.
2. `normalize(circ)`: diagonal change of basis (stored = lambda * true).  One coefficient
   per free row becomes 1; S-box inputs may be scaled since (lx)^5 = l^5 x^5.  Checked again.
3. `emit_yul(circ, kmax)`: fork-style Yul with lazy reduction.  Every value carries a bound
   in units of p; `add` is used while the sum stays below kmax units (5 for BN254, 2 for
   BLS12-381 Fr), `addmod` otherwise.  Checked with 256-bit add semantics against the
   reference on random inputs.

Conventions: state column vector, round = M * S(s + c); capacity 0 in lane 0; digest lane 0
(circomlib).  Inputs are reduced by the first addmod like circomlibjs.
"""
import random
import sys

from poseidon_ref import PoseidonInstance, BN254, BLS12_381


def inv(a, p):
    return pow(a, p - 2, p)


def matmul(A, B, p):
    n, m, k = len(A), len(B[0]), len(B)
    return [[sum(A[i][l] * B[l][j] for l in range(k)) % p for j in range(m)] for i in range(n)]


def matinv(A, p):
    n = len(A)
    M = [row[:] + [int(i == j) for j in range(n)] for i, row in enumerate(A)]
    for c in range(n):
        piv = next(r for r in range(c, n) if M[r][c] % p)
        M[c], M[piv] = M[piv], M[c]
        iv = inv(M[c][c], p)
        M[c] = [x * iv % p for x in M[c]]
        for r in range(n):
            if r != c and M[r][c]:
                f = M[r][c]
                M[r] = [(x - f * y) % p for x, y in zip(M[r], M[c])]
    return [row[n:] for row in M]


def sparse_factor(N, p):
    """N = B * A with A = diag(1, N_hat) and B sparse: row0 = (N00, N[0,1:] N_hat^-1),
    column 0 below = N[1:,0], identity elsewhere.  Returns (v, w, A)."""
    t = len(N)
    Nh = [row[1:] for row in N[1:]]
    Nhi = matinv(Nh, p)
    v = [N[0][0]] + [sum(N[0][1 + l] * Nhi[l][j] for l in range(t - 1)) % p for j in range(t - 1)]
    w = [N[i][0] for i in range(1, t)]
    A = [[int(i == j) for j in range(t)] for i in range(t)]
    for i in range(1, t):
        for j in range(1, t):
            A[i][j] = Nh[i - 1][j - 1]
    return v, w, A


class Circuit:
    """Optimised (and optionally normalised) Poseidon circuit.

    rounds: list of dicts
      {"kind": "full", "consts": [t] (pre-S-box, stored units), "rows": [t][t] coefficients,
       "row_consts": [t], "sbox_lanes": set of lanes going through the S-box (lane 0 of round 0 is
       the constant K instead), "K": constant y0 for round 0 or None}
      {"kind": "partial", "k": const on lane 0, "v": [t] read-row coefficients, "w": [t-1]}
      last round: kind "last": consts [t], row: [t] coefficients (row 0 of M)
    """

    def __init__(self, inst):
        self.inst = inst
        self.p, self.t = inst.p, inst.t
        self.rounds = []

    # ---------------------------------------------------------------- evaluation (exact)
    def evaluate(self, inputs, scaled=False):
        p, t = self.p, self.t
        lam = getattr(self, "lane_scale_in", None) if scaled else None
        s = [None] + [x % p for x in inputs]           # lane 0 unused in round 0
        for rd in self.rounds:
            if rd["kind"] == "full":
                y = []
                for i in range(t):
                    if i == 0 and rd["K"] is not None:
                        y.append(rd["K"])
                    else:
                        x = (s[i] + rd["consts"][i]) % p
                        y.append(pow(x, self.inst.alpha, p))
                s = [(sum(rd["rows"][i][j] * y[j] for j in range(t)) + rd["row_consts"][i]) % p for i in range(t)]
            elif rd["kind"] == "partial":
                x = (s[0] + rd["k"]) % p
                y = pow(x, self.inst.alpha, p)
                new0 = (rd["v"][0] * y + sum(rd["v"][j] * s[j] for j in range(1, t)) + rd.get("row_const", 0)) % p
                s = [new0] + [(s[i] + rd["w"][i - 1] * y) % p for i in range(1, t)]
            else:  # last
                y = [pow((s[i] + rd["consts"][i]) % p, self.inst.alpha, p) for i in range(t)]
                return sum(rd["row"][j] * y[j] for j in range(t)) % p
        raise RuntimeError("no last round")


def optimize(inst):
    p, t, a = inst.p, inst.t, inst.alpha
    R_F, R_P = inst.R_F, inst.R_P
    R_f = R_F // 2
    R = R_F + R_P
    M = inst.mds
    C = [inst.round_constants[r * t:(r + 1) * t] for r in range(R)]

    # --- sparse factorisation, backwards over the partial rounds
    sparse = {}
    N = [row[:] for row in M]
    for r in range(R_f + R_P - 1, R_f - 1, -1):
        v, w, A = sparse_factor(N, p)
        sparse[r] = (v, w, A)
        N = matmul(A, M, p)          # effective matrix of the previous round
    P = N                             # = A_first * M, used by round R_f - 1
    A_of = {r: sparse[r][2] for r in sparse}

    circ = Circuit(inst)
    carry = [0] * t
    for r in range(R):
        c = [(C[r][i] + carry[i]) % p for i in range(t)]      # s-space (full rounds)
        carry_in = carry
        carry = [0] * t
        if r < R_f:                                            # first-half full rounds
            rows = P if r == R_f - 1 else M
            K = pow(c[0], a, p) if r == 0 else None            # capacity lane is 0 in round 0
            rd = {"kind": "full", "consts": c, "rows": [row[:] for row in rows], "row_consts": [0] * t, "K": K}
            circ.rounds.append(rd)
        elif r < R_f + R_P:                                    # partial rounds
            v, w, A = sparse[r]
            # constants live in the transformed basis z = A s; the carry is already in z-space
            cz = [(sum(A[i][j] * C[r][j] for j in range(t)) + carry_in[i]) % p for i in range(t)]
            k, chat = cz[0], cz[1:]
            # lanes 1.. constants pass through the sparse layer: carry = B (0, chat)
            carry = [sum(v[j] * chat[j - 1] for j in range(1, t)) % p] + chat
            circ.rounds.append({"kind": "partial", "k": k, "v": v, "w": w})
        elif r < R - 1:                                        # second-half full rounds
            circ.rounds.append({"kind": "full", "consts": c, "rows": [row[:] for row in M],
                                "row_consts": [0] * t, "K": None})
        else:                                                  # last round: digest = lane 0
            circ.rounds.append({"kind": "last", "consts": c, "row": M[0][:]})
    # fold the constant S-box output of round 0 into round 1's constants: M[:,0]*K
    rd0, rd1 = circ.rounds[0], circ.rounds[1]
    for i in range(t):
        rd1["consts"][i] = (rd1["consts"][i] + rd0["rows"][i][0] * rd0["K"]) % p
        rd0["rows"][i][0] = 0
    rd0["K"] = 0
    return circ


def normalize(circ):
    """Diagonal change of basis.  Returns a new Circuit whose stored values are lambda*true;
    the digest row keeps lambda = 1.  scale[i] = current stored scale of lane i."""
    p, t, a = circ.p, circ.t, circ.inst.alpha
    out = Circuit(circ.inst)
    scale = [1] * t                     # inputs are true values
    lane_fixed = [False] * t
    for idx, rd in enumerate(circ.rounds):
        if rd["kind"] == "full":
            consts = [rd["consts"][i] * scale[i] % p for i in range(t)]      # stored X = lam (x + c)
            yscale = [pow(scale[i], a, p) for i in range(t)]                  # y stored with lam^5
            if rd["K"] is not None and rd["K"] == 0 and idx == 0:
                yscale[0] = 1
            new_rows, new_scale = [], []
            for i in range(t):
                coef = [rd["rows"][i][j] * inv(yscale[j], p) % p if yscale[j] else 0 for j in range(t)]
                # normalise the first non-zero coefficient of this row
                j_star = next(j for j in range(t) if coef[j])
                lam = inv(coef[j_star], p)
                new_rows.append([c * lam % p for c in coef])
                new_scale.append(lam)
            out.rounds.append({"kind": "full", "consts": consts, "rows": new_rows,
                               "row_consts": [rd["row_consts"][i] * new_scale[i] % p for i in range(t)],
                               "K": rd["K"]})
            scale = new_scale
        elif rd["kind"] == "partial":
            k = rd["k"] * scale[0] % p
            ys = pow(scale[0], a, p)
            # read row: coefficient of y normalised to 1 -> lam_out = ys / v0
            lam = ys * inv(rd["v"][0], p) % p
            v = [1] + [rd["v"][j] * lam % p * inv(scale[j], p) % p for j in range(1, t)]
            w = [rd["w"][i - 1] * scale[i] % p * inv(ys, p) % p for i in range(1, t)]
            out.rounds.append({"kind": "partial", "k": k, "v": v, "w": w})
            scale = [lam] + scale[1:]
        else:
            consts = [rd["consts"][i] * scale[i] % p for i in range(t)]
            yscale = [pow(scale[i], a, p) for i in range(t)]
            row = [rd["row"][j] * inv(yscale[j], p) % p for j in range(t)]   # digest lambda = 1
            out.rounds.append({"kind": "last", "consts": consts, "row": row})
    return out


# ------------------------------------------------------------------------- Yul emission
class Emitter:
    """Fork-style Yul with unit-tracked lazy reduction."""

    def __init__(self, circ, kmax, name):
        self.circ, self.kmax, self.name = circ, kmax, name
        self.lines = []
        self.nv = 0
        self.declared = set()

    def var(self, prefix="v"):
        self.nv += 1
        return f"{prefix}{self.nv}"

    def hexk(self, x):
        return f"0x{x:x}"

    def emit(self, line):
        self.lines.append(line)

    def let(self, expr, prefix="v"):
        n = self.var(prefix)
        self.emit(f"let {n} := {expr}")
        return n

    def add_terms(self, terms, reduce_last=False, force_addmod=False):
        """terms: list of (expr, units).  Returns (expr, units) summing with add/addmod so that
        no intermediate exceeds kmax units.  Terms are combined pairwise, largest first.
        reduce_last: the final combination is an addmod (result < p)."""
        terms = sorted(terms, key=lambda x: -x[1])
        while len(terms) > 1:
            (ea, ua), (eb, ub) = terms[0], terms[1]
            rest = terms[2:]
            last = len(terms) == 2
            if ua + ub <= self.kmax and not (reduce_last and last) and not (force_addmod and last):
                terms = [(f"add({ea}, {eb})", ua + ub)] + rest
            else:
                terms = [(f"addmod({ea}, {eb}, F)", 1)] + rest
            terms.sort(key=lambda x: -x[1])
        return terms[0]

    def mul(self, expr, coef):
        return f"mulmod({expr}, {self.hexk(coef)}, F)"

    def sbox(self, x, k_next=None):
        """x: (name, units) -> y name (1 unit).  Two statements in the fork's shape."""
        sq = self.let(f"mulmod({x}, {x}, F)", "sq")
        return self.let(f"mulmod(mulmod({sq}, {sq}, F), {x}, F)", "y")

    def build_flat(self):
        """SSA form (one `let` per value): what the stack scheduler consumes.  Not solc-compilable
        for large instances (stack too deep), see build() for the block-scoped form."""
        circ, p, t = self.circ, self.circ.p, self.circ.t
        self.lines, self.nv = [], 0
        self.emit(f"let F := {self.hexk(p)}")
        lanes = [None] * t
        for idx, rd in enumerate(circ.rounds):
            if rd["kind"] == "full":
                ys = [None] * t
                for i in range(t):
                    if idx == 0 and i == 0:
                        continue
                    if idx == 0:
                        x = self.let(f"addmod(calldataload({4 + 32 * (i - 1)}), {self.hexk(rd['consts'][i])}, F)", "x")
                    else:
                        x = lanes[i][0]
                    ys[i] = (self.sbox(x), 1)
                nxt = circ.rounds[idx + 1]
                new = []
                for i in range(t):
                    terms = []
                    for j in range(t):
                        c = rd["rows"][i][j]
                        if c == 0 or ys[j] is None:
                            continue
                        terms.append((ys[j][0], 1) if c == 1 else (self.mul(ys[j][0], c), 1))
                    if rd["row_consts"][i]:
                        terms.append((self.hexk(rd["row_consts"][i]), 1))
                    nc = nxt["consts"][i] if nxt["kind"] in ("full", "last") else (nxt["k"] if i == 0 else 0)
                    if nc:
                        terms.append((self.hexk(nc), 1))
                    e, u = self.add_terms(terms)
                    new.append((self.let(e, "s"), u))
                lanes = new
            elif rd["kind"] == "partial":
                x, xu = lanes[0]
                y = self.sbox(x)
                nxt = circ.rounds[idx + 1]
                terms = [(y, 1)] + [(self.mul(lanes[j][0], rd["v"][j]), 1) for j in range(1, t)]
                nc = nxt["k"] if nxt["kind"] == "partial" else nxt["consts"][0]
                if nc:
                    terms.append((self.hexk(nc), 1))
                e, u = self.add_terms(terms)
                new = [(self.let(e, "s"), u)]
                for i in range(1, t):
                    terms = [lanes[i], (self.mul(y, rd["w"][i - 1]), 1)]
                    if nxt["kind"] in ("full", "last") and nxt["consts"][i]:
                        terms.append((self.hexk(nxt["consts"][i]), 1))
                    stagger = self.kmax == 2 and (idx + i) % 2 == 0
                    e, u = self.add_terms(terms, force_addmod=stagger)
                    new.append((self.let(e, "l"), u))
                lanes = new
            else:
                ys = [self.sbox(lanes[i][0]) for i in range(t)]
                terms = [(ys[j], 1) if rd["row"][j] == 1 else (self.mul(ys[j], rd["row"][j]), 1) for j in range(t) if rd["row"][j]]
                e, u = self.add_terms(terms, reduce_last=True)
                assert u == 1
                out = self.let(e, "out")
                self.emit(f"mstore(0, {out})")
                self.emit("return(0, 0x20)")
        body = "\n".join("            " + l for l in self.lines)
        n = t - 1
        return f"""// SPDX-License-Identifier: MIT
pragma solidity 0.7.6;

/// @notice Flat (SSA) form of the optimised Poseidon body consumed by gen/build.py; see the
///         block-scoped file of the same name for the solc-compilable reference.
library {self.name} {{
    function hash(uint256[{n}] calldata) external pure returns (uint256) {{
        assembly {{
{body}
        }}
    }}
}}
"""

    def build(self):
        circ, p, t = self.circ, self.circ.p, self.circ.t
        self.emit(f"let F := {self.hexk(p)}")
        # persistent lane variables l0..l{t-1}; temporaries live inside per-round blocks
        L = [f"l{i}" for i in range(t)]
        for i in range(t):
            self.emit(f"let {L[i]} := 0")
        lanes = [(L[i], 1) for i in range(t)]   # (name, units)
        for idx, rd in enumerate(circ.rounds):
            self.emit("{")
            if rd["kind"] == "full":
                ys = [None] * t
                for i in range(t):
                    if idx == 0 and i == 0:
                        continue                                    # capacity lane folded away
                    if idx == 0:
                        self.emit(f"{L[i]} := addmod(calldataload({4 + 32 * (i - 1)}), {self.hexk(rd['consts'][i])}, F)")
                    self.emit("{")
                    self.emit(f"let sq := mulmod({L[i]}, {L[i]}, F)")
                    self.emit(f"{L[i]} := mulmod(mulmod(sq, sq, F), {L[i]}, F)")
                    self.emit("}")
                    ys[i] = (L[i], 1)
                nxt = circ.rounds[idx + 1]
                new = []
                for i in range(t):
                    terms = []
                    for j in range(t):
                        c = rd["rows"][i][j]
                        if c == 0 or ys[j] is None:
                            continue
                        terms.append((ys[j][0], 1) if c == 1 else (self.mul(ys[j][0], c), 1))
                    if rd["row_consts"][i]:
                        terms.append((self.hexk(rd["row_consts"][i]), 1))
                    nc = nxt["consts"][i] if nxt["kind"] in ("full", "last") else (nxt["k"] if i == 0 else 0)
                    if nc:
                        terms.append((self.hexk(nc), 1))
                    e, u = self.add_terms(terms)
                    self.emit(f"let n{i} := {e}")
                    new.append((L[i], u))
                for i in range(t):
                    self.emit(f"{L[i]} := n{i}")
                lanes = new
            elif rd["kind"] == "partial":
                self.emit(f"let sq := mulmod({L[0]}, {L[0]}, F)")
                self.emit(f"let y := mulmod(mulmod(sq, sq, F), {L[0]}, F)")
                nxt = circ.rounds[idx + 1]
                terms = [("y", 1)] + [(self.mul(L[j], rd["v"][j]), 1) for j in range(1, t)]
                nc = nxt["k"] if nxt["kind"] == "partial" else nxt["consts"][0]
                if nc:
                    terms.append((self.hexk(nc), 1))
                e, u0 = self.add_terms(terms)
                self.emit(f"let n0 := {e}")
                new = [(L[0], u0)]
                for i in range(1, t):
                    terms = [lanes[i], (self.mul("y", rd["w"][i - 1]), 1)]
                    if nxt["kind"] in ("full", "last") and nxt["consts"][i]:
                        terms.append((self.hexk(nxt["consts"][i]), 1))
                    stagger = self.kmax == 2 and (idx + i) % 2 == 0
                    e, u = self.add_terms(terms, force_addmod=stagger)
                    self.emit(f"{L[i]} := {e}")
                    new.append((L[i], u))
                self.emit(f"{L[0]} := n0")
                lanes = new
            else:
                for i in range(t):
                    self.emit("{")
                    self.emit(f"let sq := mulmod({L[i]}, {L[i]}, F)")
                    self.emit(f"{L[i]} := mulmod(mulmod(sq, sq, F), {L[i]}, F)")
                    self.emit("}")
                terms = [(L[j], 1) if rd["row"][j] == 1 else (self.mul(L[j], rd["row"][j]), 1) for j in range(t) if rd["row"][j]]
                e, u = self.add_terms(terms, reduce_last=True)
                assert u == 1
                self.emit(f"mstore(0, {e})")
                self.emit("return(0, 0x20)")
            self.emit("}")
        body = "\n".join("            " + l for l in self.lines)
        n = t - 1
        return f"""// SPDX-License-Identifier: MIT
pragma solidity 0.7.6;

/// @notice Generated by gen/poseidon_opt.py: optimised Poseidon (t={t}, R_F={circ.inst.R_F}, R_P={circ.inst.R_P})
///         over the field {self.hexk(p)}, circomlib conventions (capacity 0 in lane 0, digest lane 0),
///         lazy reduction with at most {self.kmax} field-sized summands per 256-bit add.
library {self.name} {{
    function hash(uint256[{n}] calldata) external pure returns (uint256) {{
        assembly {{
{body}
        }}
    }}
}}
"""


# ------------------------------------------------------------------ Yul evaluation (256-bit)
def eval_yul(src, inputs):
    """Evaluate the assembly body with EVM semantics (add mod 2^256, addmod/mulmod exact)."""
    sys.path.insert(0, __import__("os").path.dirname(__file__))
    from yuldag import parse_library
    import tempfile, os
    fd, path = tempfile.mkstemp(suffix=".sol")
    os.write(fd, src.encode())
    os.close(fd)
    dag, stmts = parse_library(path)
    os.unlink(path)
    M256 = 1 << 256
    val = {}

    def ev(n):
        if n in val:
            return val[n]
        node = dag.nodes[n]
        if node.kind == "const":
            v = node.val
        elif node.kind == "calldataload":
            i = (node.val - 4) // 32
            v = inputs[i] % M256
        else:
            args = [ev(a) for a in node.args]
            if node.kind == "add":
                v = (args[0] + args[1]) % M256
            elif node.kind == "mulmod":
                v = (args[0] * args[1]) % args[2]
            elif node.kind == "addmod":
                v = (args[0] + args[1]) % args[2]
            elif node.kind == "mod":
                v = args[0] % args[1]
            else:
                raise ValueError(node.kind)
        val[n] = v
        return v

    out = [st for st in stmts if st[0] == "mstore"][0][2]
    return ev(out)


def check(inst, kmax, name, n_random=300, seed=1):
    circ = optimize(inst)
    rnd = random.Random(seed)
    p, t = inst.p, inst.t
    vectors = [[1, 2, 3][:t - 1], [0] * (t - 1), [p - 1] * (t - 1)] + \
        [[rnd.getrandbits(256) for _ in range(t - 1)] for _ in range(n_random)]
    for v in vectors:
        assert circ.evaluate(v) == inst.hash(v), "optimised circuit mismatch"
    norm = normalize(circ)
    for v in vectors:
        assert norm.evaluate(v) == inst.hash(v), "normalised circuit mismatch"
    src = Emitter(norm, kmax, name).build()
    for v in vectors:
        assert eval_yul(src, v) == inst.hash(v), f"yul mismatch on {v}"
    return src


if __name__ == "__main__":
    which = sys.argv[1]
    if which == "bn254":
        p, n, kmax = BN254, 254, 5
    else:
        p, n, kmax = BLS12_381, 255, 2
    t, R_F, R_P = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
    name = sys.argv[5]
    out = sys.argv[6]
    inst = PoseidonInstance(p, n, t, R_F, R_P)
    src = check(inst, kmax, name)
    open(out, "w").write(src)
    norm = normalize(optimize(inst))
    flat = Emitter(norm, kmax, name).build_flat()
    rnd = random.Random(2)
    for v in [[1, 2, 3][:t - 1], [p - 1] * (t - 1)] + [[rnd.getrandbits(256) for _ in range(t - 1)] for _ in range(100)]:
        assert eval_yul(flat, v) == inst.hash(v), "flat yul mismatch"
    flat_path = out.replace(".sol", ".flat.sol")
    open(flat_path, "w").write(flat)
    print(f"{name}: optimised circuit, normalised circuit, block Yul and flat Yul all match the reference; wrote {out} and {flat_path}")
