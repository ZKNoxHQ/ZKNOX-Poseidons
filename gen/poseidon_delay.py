"""Optimised Poseidon with delay-line partial rounds (no lane reductions).

The partial rounds are a linear time-invariant system driven by the S-box output y:
    l' = N l + b y,   X' = M00 y + m.l + const        (N = M[1:,1:], b = M[1:,0], m = M[0,1:])
`poseidon_opt.py` realises it in integrator form (l_j' = l_j + w_j y): 2(t-1) multiplications,
but each lane accumulates one field-sized summand per round and must be reduced every few
rounds (one `addmod` per lane every 5 rounds on BN254).

Here the same system is put in controller canonical form, z = T^-1 l with T = [b, N b - a1 b, ...]:
    z_1' = y + a_1 z_1 + ... + a_n z_n        (a = characteristic polynomial of N)
    z_k' = z_{k-1}                            (pure delay: a renaming, no operation)
    X'   = y + c_1 z_1 + ... + c_n z_n + k    (c = m T, one constant per round)
Still 2(t-1) multiplications per round (the per-round scaling of X and z_1 puts the
coefficient of y to 1 in both sums), every value is a sum of at most t+1 field-sized
terms, and nothing accumulates: the partial rounds need no `addmod` at all when
t+1 <= floor(2^256 / p), i.e. t <= 4 on BN254.  The basis change T^-1 is merged into the
linear layer of the last full round before the partial rounds; T is applied once at the
exit (t-1 rows of t-1 terms, one coefficient per row normalised by the S-box input scale).

Conventions as in poseidon_opt.py: circomlib (capacity 0 in lane 0, digest lane 0), inputs
reduced by the first addmod, stored value = scale * true value, (lx)^5 = l^5 x^5.

    python3 poseidon_delay.py bn254 3 8 57 PoseidonT3BN254 ../yul/PoseidonT3_bn254.sol [delay|integrator]
"""
import random
import sys

from poseidon_ref import PoseidonInstance, BN254, BLS12_381
from poseidon_opt import inv, matmul, matinv, eval_yul


def charpoly_a(N, p):
    """a_1..a_n with N^n = a_1 N^(n-1) + ... + a_n I  (Faddeev-LeVerrier)."""
    n = len(N)
    I = [[int(i == j) for j in range(n)] for i in range(n)]
    Mk = I
    a = []
    for k in range(1, n + 1):
        NM = matmul(N, Mk, p)
        c = (-sum(NM[i][i] for i in range(n)) * inv(k, p)) % p      # coefficient of x^(n-k)
        a.append((-c) % p)
        Mk = [[(NM[i][j] + (c if i == j else 0)) % p for j in range(n)] for i in range(n)]
    return a


def controller_basis(N, b, p):
    """T with T^-1 N T = [[a_1..a_n],[1,0,..],[0,1,..]] and T^-1 b = e_1."""
    n = len(N)
    a = charpoly_a(N, p)
    cols = [b[:]]
    for j in range(1, n):
        Nt = [sum(N[i][l] * cols[-1][l] for l in range(n)) % p for i in range(n)]
        cols.append([(Nt[i] - a[j - 1] * b[i]) % p for i in range(n)])
    T = [[cols[j][i] for j in range(n)] for i in range(n)]
    Ti = matinv(T, p)
    C = matmul(matmul(Ti, N, p), T, p)
    assert C[0] == a and all(C[i][j] == int(j == i - 1) for i in range(1, n) for j in range(n)), "not controllable"
    assert [sum(Ti[i][l] * b[l] for l in range(n)) % p for i in range(n)] == [1] + [0] * (n - 1)
    return T, Ti, a


class Val:
    __slots__ = ("name", "scale", "units")

    def __init__(self, name, scale, units):
        self.name, self.scale, self.units = name, scale, units


class DelayEmitter:
    """Emits the flat (SSA) form for the stack scheduler and the block-scoped form for solc."""

    def __init__(self, inst, kmax, name, flat):
        self.inst, self.kmax, self.name, self.flat = inst, kmax, name, flat
        self.p, self.t = inst.p, inst.t
        self.lines, self.nv, self.stats = [], 0, {"mulmod": 0, "addmod": 0, "add": 0}

    # ------------------------------------------------------------------ low level
    def hexk(self, x):
        return f"0x{x:x}"

    def emit(self, line):
        self.lines.append(line)
        for k in ("mulmod", "addmod"):
            self.stats[k] += line.count(k + "(")
        self.stats["add"] += line.count("add(")

    def let(self, expr, prefix="v"):
        self.nv += 1
        n = f"{prefix}{self.nv}"
        self.emit(f"let {n} := {expr}")
        return n

    def add_terms(self, terms, reduce_last=False):
        """terms: [(expr, units)].  add while the sum stays within kmax field-sized summands."""
        terms = sorted(terms, key=lambda x: -x[1])
        if len(terms) == 1 and reduce_last and terms[0][1] > 1:
            return f"mod({terms[0][0]}, F)", 1
        while len(terms) > 1:
            (ea, ua), (eb, ub) = terms[0], terms[1]
            last = len(terms) == 2
            if ua + ub <= self.kmax and not (reduce_last and last):
                terms = [(f"add({ea}, {eb})", ua + ub)] + terms[2:]
            else:
                terms = [(f"addmod({ea}, {eb}, F)", 1)] + terms[2:]
            terms.sort(key=lambda x: -x[1])
        return terms[0]

    def linear(self, srcs, coefs, const, unit_src=None, reduce_last=False, out_scale=None):
        """true value = sum coefs[j] * srcs[j] + const.  Returns (expr, units, scale): the stored
        value is scale * true, with the coefficient of srcs[unit_src] equal to 1."""
        p = self.p
        idx = [j for j in range(len(srcs)) if coefs[j] % p]
        if out_scale is None:
            j0 = unit_src if unit_src is not None else idx[0]
            mu = srcs[j0].scale * inv(coefs[j0], p) % p
        else:
            mu = out_scale
        terms = []
        for j in idx:
            c = mu * coefs[j] % p * inv(srcs[j].scale, p) % p
            terms.append((srcs[j].name, srcs[j].units) if c == 1 else (f"mulmod({srcs[j].name}, {self.hexk(c)}, F)", 1))
        k = mu * const % p
        if k:
            terms.append((self.hexk(k), 1))
        e, u = self.add_terms(terms, reduce_last)
        return e, u, mu

    def sbox(self, v, slot):
        a = self.inst.alpha
        assert a == 5
        if self.flat:
            sq = self.let(f"mulmod({v.name}, {v.name}, F)", "sq")
            y = self.let(f"mulmod(mulmod({sq}, {sq}, F), {v.name}, F)", "y")
        else:
            self.emit("{")
            self.emit(f"let sq := mulmod({v.name}, {v.name}, F)")
            self.emit(f"{v.name} := mulmod(mulmod(sq, sq, F), {v.name}, F)")
            self.emit("}")
            y = v.name
        return Val(y, pow(v.scale, a, self.p), 1)

    def make(self, lin, slot, do_sbox=False):
        """Materialise a new value (expr, units, scale); optionally send it through the S-box at
        once, so that the scheduler can park the modulus under it while it is being summed."""
        e, u, mu = lin
        if self.flat:
            v = Val(self.let(e, "s"), mu, u)
        else:
            self.emit(f"let n{slot} := {e}")
            v = Val(f"n{slot}", mu, u)
        return self.sbox(v, slot) if do_sbox else v

    def commit(self, state, new):
        """new: {slot: Val}; a Val that already lives in a slot is a move (delay line)."""
        out = list(state)
        if self.flat:
            for s, v in new.items():
                out[s] = v
            return out
        moves = [s for s, v in new.items() if v.name.startswith("l")]
        for s in sorted(moves, reverse=True):                       # a delay line shifts upwards
            self.emit(f"l{s} := {new[s].name}")
        for s, v in new.items():
            if s not in moves:
                self.emit(f"l{s} := {v.name}")
            out[s] = Val(f"l{s}", v.scale, v.units)
        return out

    # ------------------------------------------------------------------ the circuit
    def build(self):
        """State between layers: slot i holds the S-box OUTPUT of lane i (full rounds), or
        slot 0 = y and slots 1..n = z_1..z_n (partial rounds)."""
        inst, p, t = self.inst, self.p, self.t
        n = t - 1
        R_f, R_P = inst.R_F // 2, inst.R_P
        R = inst.R_F + R_P
        M = inst.mds
        C = [inst.round_constants[r * t:(r + 1) * t] for r in range(R)]
        N = [row[1:] for row in M[1:]]
        b = [M[i][0] for i in range(1, t)]
        m = M[0][1:]
        T, Ti, a = controller_basis(N, b, p)
        c = [sum(m[l] * T[l][k] for l in range(n)) % p for k in range(n)]
        TiM = matmul(Ti, [row[:] for row in M[1:]], p)             # rows producing z from the y's

        self.emit(f"let F := {self.hexk(p)}")
        if not self.flat:
            for i in range(t):
                self.emit(f"let l{i} := 0")

        def block_open():
            if not self.flat:
                self.emit("{")

        def block_close():
            if not self.flat:
                self.emit("}")

        # ---- round 0: capacity lane is the constant C0[0]^5, inputs reduced by the addmod
        K0 = pow(C[0][0], inst.alpha, p)
        state = [None] * t
        block_open()
        for i in range(1, t):
            e = f"addmod(calldataload({4 + 32 * (i - 1)}), {self.hexk(C[0][i])}, F)"
            if self.flat:
                state[i] = self.sbox(Val(self.let(e, "x"), 1, 1), i)
            else:
                self.emit(f"l{i} := {e}")
                state[i] = self.sbox(Val(f"l{i}", 1, 1), i)
        block_close()

        def layer(state, rows, consts, sbox_mask, order):
            """new_i = rows_i . y + consts_i, sent through the S-box where sbox_mask[i]."""
            first = state[0] is None
            srcs = [y for y in state if y is not None]
            new = {}
            block_open()
            for i in order:
                co = [rows[i][j] for j in range(t) if state[j] is not None]
                k = consts[i] + (rows[i][0] * K0 if first else 0)
                new[i] = self.make(self.linear(srcs, co, k % p), i, sbox_mask[i])
            out = self.commit(state, new)
            block_close()
            return out

        # ---- first-half full rounds; the last linear layer lands in the delay-line basis
        for r in range(R_f - 1):
            state = layer(state, M, C[r + 1], [True] * t, range(t))
        state = layer(state, [M[0]] + TiM, [C[R_f][0]] + [0] * n, [True] + [False] * n,
                      list(range(1, t)) + [0])

        # ---- partial rounds: slot 0 = y = X^5, slots 1..n = z_1..z_n
        delta = [0] * n
        for r in range(R_f, R_f + R_P):
            dc = [(delta[i] + C[r][1 + i]) % p for i in range(n)]
            kappa = (sum(m[i] * dc[i] for i in range(n)) + C[r + 1][0]) % p
            delta = [sum(N[i][l] * dc[l] for l in range(n)) % p for i in range(n)]
            block_open()
            y, z = state[0], state[1:]
            srcs = [y] + z
            new = {1: self.make(self.linear(srcs, [1] + a, 0, unit_src=0), 1)}
            for k in range(2, t):
                new[k] = z[k - 2]                                   # z_k' = z_{k-1}
            new[0] = self.make(self.linear(srcs, [M[0][0]] + c, kappa, unit_src=0), 0, True)
            state = self.commit(state, new)
            block_close()

        # ---- exit: lanes back to the round basis, l = T z + delta, straight into the S-boxes
        r_e = R_f + R_P
        block_open()
        z = state[1:]
        new = {1 + j: self.make(self.linear(z, T[j], (delta[j] + C[r_e][1 + j]) % p), 1 + j, True) for j in range(n)}
        state = self.commit(state, new)
        block_close()

        # ---- second-half full rounds, then the digest row
        for r in range(r_e, R - 1):
            state = layer(state, M, C[r + 1], [True] * t, range(t))
        block_open()
        e, u, _ = self.linear(state, M[0], 0, reduce_last=True, out_scale=1)
        assert u == 1
        if self.flat:
            e = self.let(e, "out")
        self.emit(f"mstore(0, {e})")
        self.emit("return(0, 0x20)")
        block_close()

        return self.wrap("delay-line (controller canonical) form: 2(t-1) multiplications per round and no lane reduction")

    def wrap(self, form_note):
        inst, t = self.inst, self.t
        body = "\n".join("            " + l for l in self.lines)
        form = ("Flat (SSA) form consumed by gen/build.py" if self.flat
                else "Block-scoped form, compilable by solc (reference for the scheduled bytecode)")
        return f"""// SPDX-License-Identifier: MIT
pragma solidity 0.7.6;

/// @notice Generated by gen/poseidon_delay.py: optimised Poseidon (t={t}, R_F={inst.R_F}, R_P={inst.R_P})
///         over the field {self.hexk(self.p)}, circomlib conventions (capacity 0 in lane 0, digest lane 0).
///         Partial rounds in {form_note};
///         every S-box input goes through its S-box as soon as it is summed; at most {self.kmax}
///         field-sized summands per 256-bit add.
///         {form}.
library {self.name} {{
    function hash(uint256[{t - 1}] calldata) external pure returns (uint256) {{
        assembly {{
{body}
        }}
    }}
}}
"""

    def build_integrator(self):
        """Same layering with the sparse (integrator) partial rounds of poseidon_opt.optimize:
        X' = v0 y + v.l + k, l_j' = l_j + w_j y, lanes reduced when they reach kmax summands."""
        from poseidon_opt import optimize
        circ = optimize(self.inst)
        p, t = self.p, self.t
        rounds = circ.rounds
        self.emit(f"let F := {self.hexk(p)}")
        if not self.flat:
            for i in range(t):
                self.emit(f"let l{i} := 0")

        def bo():
            if not self.flat:
                self.emit("{")

        def bc():
            if not self.flat:
                self.emit("}")

        def nxt_consts(idx):
            nx = rounds[idx + 1]
            if nx["kind"] == "partial":
                return [nx["k"]] + [0] * (t - 1), [True] + [False] * (t - 1)
            return list(nx["consts"]), [True] * t

        state = [None] * t
        bo()
        for i in range(1, t):
            e = f"addmod(calldataload({4 + 32 * (i - 1)}), {self.hexk(rounds[0]['consts'][i])}, F)"
            if self.flat:
                state[i] = self.sbox(Val(self.let(e, "x"), 1, 1), i)
            else:
                self.emit(f"l{i} := {e}")
                state[i] = self.sbox(Val(f"l{i}", 1, 1), i)
        bc()
        for idx, rd in enumerate(rounds):
            bo()
            if rd["kind"] == "full":
                consts, mask = nxt_consts(idx)
                srcs = [y for y in state if y is not None]
                order = list(range(t)) if all(mask) else list(range(1, t)) + [0]
                new = {}
                for i in order:
                    co = [rd["rows"][i][j] for j in range(t) if state[j] is not None]
                    new[i] = self.make(self.linear(srcs, co, consts[i]), i, mask[i])
                state = self.commit(state, new)
            elif rd["kind"] == "partial":
                consts, mask = nxt_consts(idx)
                y, lanes = state[0], state[1:]
                new = {}
                for i in range(1, t):
                    new[i] = self.make(self.linear([lanes[i - 1], y], [1, rd["w"][i - 1]], consts[i],
                                                   out_scale=lanes[i - 1].scale), i, mask[i])
                new[0] = self.make(self.linear([y] + lanes, rd["v"], consts[0], unit_src=0), 0, True)
                state = self.commit(state, new)
            else:
                e, u, _ = self.linear(state, rd["row"], 0, reduce_last=True, out_scale=1)
                assert u == 1
                if self.flat:
                    e = self.let(e, "out")
                self.emit(f"mstore(0, {e})")
                self.emit("return(0, 0x20)")
            bc()
        return self.wrap("integrator (sparse) form: 2(t-1) multiplications per round, lanes reduced every few rounds")


def generate(inst, kmax, name, form="delay", n_random=300, seed=1):
    p, t = inst.p, inst.t
    rnd = random.Random(seed)
    vectors = [list(range(1, t)), [0] * (t - 1), [p - 1] * (t - 1), [p] * (t - 1), [2 ** 256 - 1] * (t - 1),
               [2 ** 255] * (t - 1)] + [[rnd.getrandbits(256) for _ in range(t - 1)] for _ in range(n_random)]
    out = {}
    for flat in (False, True):
        em = DelayEmitter(inst, kmax, name, flat)
        src = em.build() if form == "delay" else em.build_integrator()
        for v in vectors:
            assert eval_yul(src, v) == inst.hash(v), f"{'flat' if flat else 'block'} yul mismatch on {v}"
        out[flat] = (src, em.stats)
    return out, len(vectors)


if __name__ == "__main__":
    which = sys.argv[1]
    p, nbits, kmax = (BN254, 254, 5) if which == "bn254" else (BLS12_381, 255, 2)
    t, R_F, R_P = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
    name, path = sys.argv[5], sys.argv[6]
    form = sys.argv[7] if len(sys.argv) > 7 else "delay"
    assert form in ("delay", "integrator")
    inst = PoseidonInstance(p, nbits, t, R_F, R_P)
    res, nvec = generate(inst, kmax, name, form)
    open(path, "w").write(res[False][0])
    open(path.replace(".sol", ".flat.sol"), "w").write(res[True][0])
    print(f"{name}: {form} form, block and flat Yul match the reference on {nvec} inputs; "
          f"ops {res[True][1]}; wrote {path} and {path.replace('.sol', '.flat.sol')}")
