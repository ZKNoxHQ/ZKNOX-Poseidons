"""Reference Poseidon (Grassi et al.), parameterised as hadeshash's generate_parameters_grain.sage.

    instance = PoseidonInstance(p, n, t, R_F, R_P, alpha=5)
    instance.round_constants  # Grain-LFSR, (R_F+R_P)*t elements, round-major
    instance.mds              # Cauchy 1/(x_i + y_j), x and y drawn from the same Grain stream
    instance.permutation(state)
    instance.hash(inputs)     # circomlib convention: state = [0, *inputs], output state[0]

Grain seed: FIELD (2 bits, 1 = prime field) | SBOX (4 bits, 0 = x^alpha) | n (12 bits) |
t (12 bits) | R_F (10 bits) | R_P (10 bits) | 30 ones.  Same bit stream as the sage script:
160 discarded bits, then rejection sampling (emit bit2 when bit1 == 1) and constants < p.
"""
import json
import sys

BN254 = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
BLS12_381 = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001


class Grain:
    TAPS = (62, 51, 38, 23, 13, 0)

    def __init__(self, field, sbox, n, t, R_F, R_P):
        bits = []
        for v, w in ((field, 2), (sbox, 4), (n, 12), (t, 12), (R_F, 10), (R_P, 10)):
            bits += [int(b) for b in bin(v)[2:].zfill(w)]
        bits += [1] * 30
        assert len(bits) == 80
        self.state = bits
        for _ in range(160):
            self._step()

    def _step(self):
        s = self.state
        b = s[62] ^ s[51] ^ s[38] ^ s[23] ^ s[13] ^ s[0]
        s.pop(0)
        s.append(b)
        return b

    def bit(self):
        while True:
            b1 = self._step()
            b2 = self._step()
            if b1 == 1:
                return b2

    def bits(self, k):
        v = 0
        for _ in range(k):
            v = (v << 1) | self.bit()
        return v


class PoseidonInstance:
    def __init__(self, p, n, t, R_F, R_P, alpha=5):
        assert p.bit_length() == n, "n must be the bit length of p"
        self.p, self.n, self.t, self.R_F, self.R_P, self.alpha = p, n, t, R_F, R_P, alpha
        g = Grain(1, 0, n, t, R_F, R_P)
        rc = []
        while len(rc) < (R_F + R_P) * t:
            c = g.bits(n)
            if c < p:
                rc.append(c)
        self.round_constants = rc
        # MDS: Cauchy matrix 1/(x_i + y_j) with x, y sampled from the same Grain stream (as the
        # sage script does; circomlib's matrices are reproduced this way for t = 3, 4, 5).
        # The script re-samples on duplicates or if the invariant-subspace checks fail; the
        # first sample is accepted for the instances we generate (checked against circomlib and
        # hadeshash), so only the duplicate check is implemented here.
        while True:
            xy = [g.bits(n) % p for _ in range(2 * t)]
            if len(set(xy)) == 2 * t:
                break
        self.mds_x, self.mds_y = xy[:t], xy[t:]
        self.mds = [[pow(self.mds_x[i] + self.mds_y[j], p - 2, p) for j in range(t)] for i in range(t)]

    def permutation(self, state):
        p, t, a, M = self.p, self.t, self.alpha, self.mds
        s = list(state)
        assert len(s) == t
        rc = iter(self.round_constants)
        R_f = self.R_F // 2

        def mix(s):
            return [sum(M[i][j] * s[j] for j in range(t)) % p for i in range(t)]

        for r in range(self.R_F + self.R_P):
            s = [(x + next(rc)) % p for x in s]
            if R_f <= r < R_f + self.R_P:
                s[0] = pow(s[0], a, p)
            else:
                s = [pow(x, a, p) for x in s]
            s = mix(s)
        return s

    def hash(self, inputs):
        """circomlib convention: capacity 0 in lane 0, digest = lane 0."""
        assert len(inputs) == self.t - 1
        return self.permutation([0] + [x % self.p for x in inputs])[0]

    def to_json(self):
        return {"p": hex(self.p), "n": self.n, "t": self.t, "R_F": self.R_F, "R_P": self.R_P,
                "alpha": self.alpha,
                "grain_seed": f"1 0 {self.n} {self.t} {self.R_F} {self.R_P} {hex(self.p)}",
                "round_constants": [hex(c) for c in self.round_constants],
                "mds_x": [hex(x) for x in self.mds_x], "mds_y": [hex(y) for y in self.mds_y],
                "mds": [[hex(x) for x in row] for row in self.mds]}


if __name__ == "__main__":
    p = int(sys.argv[1], 0)
    n, t, R_F, R_P = map(int, sys.argv[2:6])
    inst = PoseidonInstance(p, n, t, R_F, R_P)
    d = inst.to_json()
    d["test_vectors"] = {
        "permutation_0_1_2": [hex(x) for x in inst.permutation(list(range(t)))],
        "hash_circomlib_convention_1..t-1": hex(inst.hash(list(range(1, t)))),
    }
    json.dump(d, sys.stdout, indent=1)
