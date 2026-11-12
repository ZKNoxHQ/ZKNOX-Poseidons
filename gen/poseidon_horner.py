"""Optimised Poseidon for fields where only two field-sized summands fit in 256 bits
(BLS12-381 Fr: 2p < 2^256 < 3p).  Partial rounds without any `addmod`.

Same linear system as poseidon_delay.py (controller canonical form, z1' = y + a.z,
z_k' = z_(k-1), X' = M00 y + c.z + const), evaluated so that no sum ever holds three
field-sized terms:

* Horner brackets.  a.z = a_n (z_n + (a_(n-1)/a_n) (z_(n-1) + ... (a_1/a_2) z_1)): every
  bracket is `add(D, product)` with D a reduced delayed value, and it is consumed by the
  next `mulmod`, which reduces it for free.  Still 2(t-1) multiplications per round.
* The delayed values are products.  The innermost product of the z-row, U = beta * z_1, is
  what the delay line stores (it is proportional to z_1 and already reduced); z_1 itself
  (y + P + E, about 2p) is only ever consumed by `mulmod`.
* Small constants.  The state is stored shifted, z^ = z + d: the shift of the new z_1 is a
  free parameter per round, and it is chosen so that the constant E of the z-row and the
  constant K of the next X-row are both below 2^256 - 2p (20.8 % of the field each), so
  y + P + const fits in 256 bits.  E is scanned from 1 for the value followed by the longest
  run of rounds that can take E = 0 (their K staying small): most z-rows have no constant.

Every `add` is emitted only if the exact upper bounds of its operands sum below 2^256
(bounds are tracked per value: p-1 for a product or an addmod, the value for a constant);
otherwise the summation falls back to `addmod`, whose operands may be any 256-bit values.
Full rounds use the same bound-driven summation, which needs one `addmod` per row for
t <= 4.  S-box inputs go through their S-box as soon as they are summed (build.py --glue-sbox).

Conventions: circomlib (capacity 0 in lane 0, digest lane 0), inputs reduced by the first addmod,
stored value = scale * true value, (lx)^5 = l^5 x^5.

    python3 poseidon_horner.py bls 3 8 57 PoseidonT3BLS ../yul/PoseidonT3_bls12381.sol
"""
import random
import sys

from poseidon_ref import PoseidonInstance, BN254, BLS12_381
from poseidon_opt import inv, matmul, eval_yul
from poseidon_delay import controller_basis

CAP = (1 << 256) - 1


class BVal:
    """A stored value: name, scale (stored = scale * true) and exact upper bound."""
    __slots__ = ("name", "scale", "bound")

    def __init__(self, name, scale, bound):
        self.name, self.scale, self.bound = name, scale, bound


class HornerEmitter:
    _plans = {}                                         # constants plan, shared by the flat and block forms

    def __init__(self, inst, name, flat, row_horner=True):
        self.inst, self.name, self.flat = inst, name, flat
        self.p, self.t = inst.p, inst.t
        assert 2 * (self.p - 1) <= CAP, "at least two field-sized summands must fit"
        self.lines, self.nv = [], 0
        self.stats = {"mulmod": 0, "addmod": 0, "add": 0}
        self.consts = {"E0": 0, "K0": 0, "rounds": 0}
        self.scan, self.run_target = 400000, 9          # search of the shift constants
        self.row_horner = row_horner

    # ------------------------------------------------------------------ low level
    def hexk(self, x):
        return f"0x{x:x}"

    def emit(self, line):
        self.lines.append(line)
        for k in ("mulmod", "addmod"):
            self.stats[k] += line.count(k + "(")
        self.stats["add"] += line.count("add(")

    def let(self, expr, prefix):
        """flat: fresh SSA name; block: the given name, scoped to the current block."""
        if self.flat:
            self.nv += 1
            n = f"{prefix}{self.nv}"
        else:
            n = prefix
        self.emit(f"let {n} := {expr}")
        return n

    def sum_terms(self, terms, reduced=False):
        """terms: [(expr, bound)].  Returns (expr, bound) with as few addmod as possible:
        terms are packed into groups that fit in 256 bits, two groups are merged by an addmod
        (result < p) until one group is left."""
        p = self.p
        terms = list(terms)

        def chain(es):
            x = es[0]
            for e in es[1:]:
                x = f"add({x}, {e})"
            return x

        while True:
            order = sorted(range(len(terms)), key=lambda i: -terms[i][1])
            groups = []                                   # [indices, bound]
            for i in order:
                for g in groups:
                    if g[1] + terms[i][1] <= CAP:
                        g[0].append(i)
                        g[1] += terms[i][1]
                        break
                else:
                    groups.append([[i], terms[i][1]])
            if len(groups) == 1:
                g = groups[0]
                if not reduced or g[1] <= p - 1:
                    return chain([terms[i][0] for i in g[0]]), g[1]
                assert len(g[0]) >= 2, "a single unreduced term cannot be reduced by addmod"
                a, b = g[0][:1], g[0][1:]
                return (f"addmod({chain([terms[i][0] for i in a])}, {chain([terms[i][0] for i in b])}, F)", p - 1)
            g0, g1 = groups[0], groups[1]
            merged = (f"addmod({chain([terms[i][0] for i in g0[0]])}, {chain([terms[i][0] for i in g1[0]])}, F)", p - 1)
            used = set(g0[0]) | set(g1[0])
            terms = [merged] + [terms[i] for i in range(len(terms)) if i not in used]

    def raw_candidates(self, srcs, coefs, const):
        """sources that can enter a row raw (coefficient 1), with the stored constant each choice
        gives; the choices whose constant leaves room for raw + product + constant come first."""
        p = self.p
        out = []
        for j in range(len(srcs)):
            if coefs[j] % p and srcs[j].bound <= p - 1:
                mu = srcs[j].scale * inv(coefs[j], p) % p
                k = mu * const % p
                out.append((k > CAP - srcs[j].bound - (p - 1), srcs[j].bound, j, mu, k))
        return sorted(out)

    def linear(self, srcs, coefs, const, reduced=False, out_scale=None):
        """true value = sum coefs[j] * srcs[j] + const.  Returns (expr, bound, scale).
        Free scale: one reduced source is taken raw, the others go through a Horner chain
        (same number of multiplications as a plain sum of products) and the raw source is chosen
        so that the stored constant is small when possible: raw + chain + constant then needs no
        addmod.  Fixed scale and no constant: the whole row is one Horner chain."""
        p = self.p
        idx = [j for j in range(len(srcs)) if coefs[j] % p]

        def chain(js, target):
            """target * sum_{j in js} coefs[j] true_j as one product (the least reduced source innermost)"""
            js = sorted(js, key=lambda j: -srcs[j].bound)
            if len(js) == 1:
                j = js[0]
                return f"mulmod({srcs[j].name}, {self.hexk(target * coefs[j] % p * inv(srcs[j].scale, p) % p)}, F)"
            if any(srcs[j].bound > p - 1 for j in js[1:]):
                return None
            e, _ = self.horner(srcs[js[0]], [srcs[j] for j in js[1:]], [coefs[j] for j in js], target, False)
            return e

        if self.row_horner:
            if out_scale is not None and const % p == 0 and len(idx) >= 2:
                e = chain(idx, out_scale)
                if e is not None:
                    return e, p - 1, out_scale
            cands = self.raw_candidates(srcs, coefs, const) if out_scale is None else []
            if cands:
                _, _, j0, mu, k = cands[0]
                others = [j for j in idx if j != j0]
                e = chain(others, mu) if others else None
                if not others or e is not None:
                    terms = [(srcs[j0].name, srcs[j0].bound)] + ([(e, p - 1)] if others else []) + ([(self.hexk(k), k)] if k else [])
                    e, b = self.sum_terms(terms, reduced)
                    return e, b, mu
        if out_scale is None:
            j0 = min(idx, key=lambda j: (srcs[j].bound, j))
            mu = srcs[j0].scale * inv(coefs[j0], p) % p
        else:
            mu = out_scale
        terms = []
        for j in idx:
            c = mu * coefs[j] % p * inv(srcs[j].scale, p) % p
            terms.append((srcs[j].name, srcs[j].bound) if c == 1
                         else (f"mulmod({srcs[j].name}, {self.hexk(c)}, F)", p - 1))
        k = mu * const % p
        if k:
            terms.append((self.hexk(k), k))
        e, b = self.sum_terms(terms, reduced)
        return e, b, mu

    def sbox(self, name, scale):
        """name holds an S-box input (any 256-bit value); returns the S-box output."""
        assert self.inst.alpha == 5
        if self.flat:
            sq = self.let(f"mulmod({name}, {name}, F)", "sq")
            y = self.let(f"mulmod(mulmod({sq}, {sq}, F), {name}, F)", "y")
        else:
            self.emit("{")
            self.emit(f"let sq := mulmod({name}, {name}, F)")
            self.emit(f"{name} := mulmod(mulmod(sq, sq, F), {name}, F)")
            self.emit("}")
            y = name
        return BVal(y, pow(scale, 5, self.p), self.p - 1)

    def horner(self, Z, D, co, out_scale, keep_inner):
        """out_scale * (co[0] z_1 + co[1] z_2 + ...), z_1 = Z (any bound, multiplied), z_(k+1) = D[k-1]
        (reduced, added raw).  Returns (expr, inner): inner is the innermost product
        beta * Z as a named BVal when keep_inner, else None."""
        p, n = self.p, len(co)
        assert n >= 2 and all(c % p for c in co), "Horner form needs t >= 3 and non-zero coefficients"
        s = D[0].scale * inv(co[1], p) % p                           # bracket = s * (co1 z2 + co0 z1)
        inner_expr = f"mulmod({Z.name}, {self.hexk(s * co[0] % p * inv(Z.scale, p) % p)}, F)"
        inner = None
        if keep_inner:
            inner = BVal(self.let(inner_expr, "u"), s * co[0] % p, p - 1)
            inner_expr = inner.name
        assert D[0].bound + p - 1 <= CAP
        B = f"add({D[0].name}, {inner_expr})"
        for i in range(2, n):
            s2 = D[i - 1].scale * inv(co[i], p) % p
            assert D[i - 1].bound + p - 1 <= CAP
            B = f"add({D[i - 1].name}, mulmod({B}, {self.hexk(s2 * inv(s, p) % p)}, F))"
            s = s2
        return f"mulmod({B}, {self.hexk(out_scale * inv(s, p) % p)}, F)", inner

    # ------------------------------------------------------------------ the circuit
    def build(self):
        """Slots: full rounds, slot i = S-box output of lane i; partial rounds, slot 0 = y,
        slot 1 = z_1 (shifted, unreduced), slot k+1 = delayed product proportional to z_(k+1)."""
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
        TiM = matmul(Ti, [row[:] for row in M[1:]], p)
        M00 = M[0][0]

        def dot(u, v):
            return sum(x * y for x, y in zip(u, v)) % p

        # constants of the partial rounds (true values, unshifted state): X' = ... + kap[q]
        delta, kap = [0] * n, []
        for r in range(R_f, R_f + R_P):
            dc = [(delta[i] + C[r][1 + i]) % p for i in range(n)]
            kap.append((dot(m, dc) + C[r + 1][0]) % p)
            delta = [dot(N[i], dc) for i in range(n)]

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

        def store(slot, v):
            """block form: move a temporary into its slot."""
            if self.flat:
                return v
            if v.name != f"l{slot}":
                self.emit(f"l{slot} := {v.name}")
            return BVal(f"l{slot}", v.scale, v.bound)

        def row(state, coefs, const, slot, do_sbox, reduced=False):
            srcs = [y for y in state if y is not None]
            co = [coefs[j] for j in range(t) if state[j] is not None]
            e, bd, mu = self.linear(srcs, co, const, reduced)
            name = self.let(e, "s" if self.flat else f"n{slot}")
            return self.sbox(name, mu) if do_sbox else BVal(name, mu, bd)

        # ---- round 0: capacity lane is the constant C0[0]^5, inputs reduced by the addmod
        K0 = pow(C[0][0], inst.alpha, p)
        state = [None] * t
        bo()
        for i in range(1, t):
            e = f"addmod(calldataload({4 + 32 * (i - 1)}), {self.hexk(C[0][i])}, F)"
            if self.flat:
                state[i] = self.sbox(self.let(e, "x"), 1)
            else:
                self.emit(f"l{i} := {e}")
                state[i] = self.sbox(f"l{i}", 1)
        bc()

        def full_layer(state, rows, consts, mask, order, reduced):
            first = state[0] is None
            bo()
            new = {}
            for i in order:
                k = (consts[i] + (rows[i][0] * K0 if first else 0)) % p
                new[i] = row(state, rows[i], k, i, mask[i], reduced[i])
            out = [store(i, new[i]) for i in range(t)]
            bc()
            return out

        # ---- first-half full rounds; the last linear layer lands in the shifted delay-line basis
        for r in range(R_f - 1):
            state = full_layer(state, M, C[r + 1], [True] * t, range(t), [False] * t)
        sh = [kap[0] * inv(c[0], p) % p] + [0] * (n - 1)            # makes the first K vanish
        state = full_layer(state, [M[0]] + TiM, [C[R_f][0]] + sh, [True] + [False] * n,
                           list(range(1, t)) + [0], [False, False] + [True] * (n - 1))

        # ---- partial rounds
        y, Z, D = state[0], state[1], state[2:]
        # scales depend only on the round index: nu = scale of y (z-row), mu = nu / M00 (X-row)
        nus, mus = [y.scale], [y.scale * inv(M00, p) % p]
        for q in range(1, R_P):
            nus.append(pow(mus[-1], 5, p))
            mus.append(nus[-1] * inv(M00, p) % p)
        small = CAP - 2 * (p - 1)

        def step(q, sh, E):
            """shift after round q when its z-row constant is E, and the constant K of round q+1"""
            shn = [(E * inv(nus[q], p) + dot(a, sh)) % p] + sh[:-1]
            return shn, (mus[q + 1] * (kap[q + 1] - dot(c, shn)) % p if q + 1 < R_P else 0)

        def zero_run(q, sh):
            """number of consecutive rounds from q on that can take E = 0"""
            k = 0
            while q + k < R_P - 1:
                sh, Kn = step(q + k, sh, 0)
                if Kn > small:
                    break
                k += 1
            return k

        # plan the constants: E = 0 whenever the next K stays small; otherwise the E (scanned from 1)
        # that keeps the next K small and is followed by the longest run of E = 0
        plan = self._plans.get((p, t, R_P, self.row_horner))
        # scales of the delayed products at the exit (geometric: U = (a1/a2) * previous U)
        Dsc = [d.scale for d in D]
        for q in range(R_P):
            Dsc = [Dsc[0] * a[0] % p * inv(a[1], p) % p] + Dsc[:-1]
        r_e = R_f + R_P

        def exit_small(shx):
            """every exit row has a raw source whose stored constant is small"""
            for j in range(n):
                kj = (delta[j] + C[r_e][1 + j] - dot(T[j], shx)) % p
                if not any(T[j][i + 1] % p and Dsc[i] * inv(T[j][i + 1], p) % p * kj % p <= small for i in range(n - 1)):
                    return False
            return True

        for q in range(R_P if plan is None else 0):
            if q == 0:
                plan = []
            K = mus[q] * (kap[q] - dot(c, sh)) % p
            shn, Kn = step(q, sh, 0)
            E = 0
            if q == R_P - 1 and self.row_horner:
                for cand in range(self.scan):
                    shc, _ = step(q, sh, cand)
                    if exit_small(shc):
                        E, shn = cand, shc
                        break
            if q < R_P - 1 and Kn > small:
                best = None
                inv_nu = inv(nus[q], p)
                base = dot(a, sh)
                for cand in range(1, self.scan):
                    shc = [(cand * inv_nu + base) % p] + sh[:-1]
                    if mus[q + 1] * (kap[q + 1] - dot(c, shc)) % p > small:
                        continue
                    run = zero_run(q + 1, shc)
                    if best is None or run > best[0]:
                        best = (run, cand, shc)
                        if run >= min(self.run_target, R_P - 2 - q):
                            break
                assert best is not None, "no small constant found"
                _, E, shn = best
            plan.append((E, K))
            sh = shn
        assert all(E <= small and K <= small for E, K in plan)
        self._plans[(p, t, R_P, self.row_horner)] = plan
        # the exit needs the final shift: replay the plan
        sh = [kap[0] * inv(c[0], p) % p] + [0] * (n - 1)
        for q in range(R_P):
            sh, _ = step(q, sh, plan[q][0])

        for q in range(R_P):
            E, K = plan[q]
            nu, mu = nus[q], mus[q]
            assert y.scale == nu
            self.consts["rounds"] += 1
            self.consts["E0"] += E == 0
            self.consts["K0"] += K == 0
            bo()
            PZ, U = self.horner(Z, D, a, nu, True)
            ez, bz = self.sum_terms([(y.name, y.bound), (PZ, p - 1)] + ([(self.hexk(E), E)] if E else []))
            nz = BVal(self.let(ez, "z" if self.flat else "nz"), nu, bz)
            PX, _ = self.horner(Z, D, c, mu, False)
            ex, _ = self.sum_terms([(y.name, y.bound), (PX, p - 1)] + ([(self.hexk(K), K)] if K else []))
            ynew = self.sbox(self.let(ex, "s" if self.flat else "nx"), mu)
            Dn = [U] + D[:-1]
            if not self.flat:
                for slot in range(n, 2, -1):                         # delay line: slots 2..n shift upwards
                    self.emit(f"l{slot} := l{slot - 1}")
                Dn = [store(2, U)] + [BVal(f"l{k + 2}", D[k - 1].scale, D[k - 1].bound) for k in range(1, n - 1)]
                nz = store(1, nz)
                ynew = store(0, ynew)
            y, Z, D = ynew, nz, Dn
            bc()

        # ---- exit: lanes back to the round basis, l = T (z^ - shift) + delta, straight into the S-boxes
        bo()
        zs = [Z] + D
        lanes = []
        for j in range(n):
            k = (delta[j] + C[r_e][1 + j] - dot(T[j], sh)) % p
            e, bd, mu = self.linear(zs, T[j], k)
            lanes.append(self.sbox(self.let(e, "s" if self.flat else f"n{1 + j}"), mu))
        state = [y] + [store(1 + j, lanes[j]) for j in range(n)]
        bc()

        # ---- second-half full rounds, then the digest row
        for r in range(r_e, R - 1):
            state = full_layer(state, M, C[r + 1], [True] * t, range(t), [False] * t)
        bo()
        e, bd, _ = self.linear(state, M[0], 0, reduced=True, out_scale=1)
        assert bd <= p - 1
        if self.flat:
            e = self.let(e, "out")
        self.emit(f"mstore(0, {e})")
        self.emit("return(0, 0x20)")
        bc()

        body = "\n".join("            " + l for l in self.lines)
        form = ("Flat (SSA) form consumed by gen/build.py" if self.flat
                else "Block-scoped form, compilable by solc (reference for the scheduled bytecode)")
        return f"""// SPDX-License-Identifier: MIT
pragma solidity 0.7.6;

/// @notice Generated by gen/poseidon_horner.py: optimised Poseidon (t={t}, R_F={inst.R_F}, R_P={R_P})
///         over the field {self.hexk(p)}, circomlib conventions (capacity 0 in lane 0, digest lane 0).
///         Partial rounds in delay-line form with Horner brackets and small constants: 2(t-1)
///         multiplications per round and no addmod; every add is proven overflow-free from the
///         exact bounds of its operands.
///         {form}.
library {self.name} {{
    function hash(uint256[{n}] calldata) external pure returns (uint256) {{
        assembly {{
{body}
        }}
    }}
}}
"""


def generate(inst, name, n_random=300, seed=1, row_horner=True):
    p, t = inst.p, inst.t
    rnd = random.Random(seed)
    vectors = [list(range(1, t)), [0] * (t - 1), [p - 1] * (t - 1), [p] * (t - 1), [2 ** 256 - 1] * (t - 1),
               [2 ** 255] * (t - 1)] + [[rnd.getrandbits(256) for _ in range(t - 1)] for _ in range(n_random)]
    out = {}
    for flat in (False, True):
        em = HornerEmitter(inst, name, flat, row_horner)
        src = em.build()
        for v in vectors:
            assert eval_yul(src, v) == inst.hash(v), f"{'flat' if flat else 'block'} yul mismatch on {v}"
        out[flat] = (src, em.stats, em.consts)
    return out, len(vectors)


if __name__ == "__main__":
    which = sys.argv[1]
    p, nbits = (BN254, 254) if which == "bn254" else (BLS12_381, 255)
    t, R_F, R_P = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
    name, path = sys.argv[5], sys.argv[6]
    inst = PoseidonInstance(p, nbits, t, R_F, R_P)
    res, nvec = generate(inst, name)
    open(path, "w").write(res[False][0])
    open(path.replace(".sol", ".flat.sol"), "w").write(res[True][0])
    print(f"{name}: Horner delay-line form, block and flat Yul match the reference on {nvec} inputs; "
          f"ops {res[True][1]}; partial rounds {res[True][2]}; wrote {path} and {path.replace('.sol', '.flat.sol')}")
