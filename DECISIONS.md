# Architecture decisions

## ADR-1 — Raw bytecode instead of Yul/Solidity for the arithmetic body

The fork's runtime is at the algorithmic floor (7 mulmod per T3 partial round; a
linear change of basis cannot go lower: t² coefficients against t²−2t+2 degrees of
freedom leaves 2(t−1) multiplications). What remains is code generation: solc's
legacy pipeline emits a DUP per variable read and SWAP+POP per assignment, 5,970 gas
of stack shuffling on T3 (1,406 DUP, 352 SWAP, 349 POP) against 4,080 gas of MULMOD.
via-IR spills the state to memory (24,457 gas). `verbatim` is rejected in inline
assembly (solc 0.8.30, error 4619), so the optimal instruction stream cannot live
inside a `library`. The body is therefore emitted directly as bytecode; the constants
and the data flow are read from the fork's Yul, which keeps the review surface to the
scheduler and the emitter (both re-simulate the stack), and lets every constant stay
covered by the fork's light-poseidon fuzzing.

## ADR-2 — Packaging: constructor that returns the runtime, plus a raw creation hex

Libraries cannot have constructors, so the artifact is a `contract` whose constructor
returns the generated runtime from a `bytes constant`. `type(PoseidonT3).creationCode`
and Foundry deployment keep working; consumers call through `IPoseidonT3` or link the
deployed address into a stub library, the pattern the shielded pool already uses for the iden3
bytecode (`tasks/overrides.ts`). The runtime serves one selector, the one the shielded pool's
existing `library PoseidonT3 { function poseidon(bytes32[2] memory) ... }` stub calls
(iden3 signature), so it is a drop-in without touching `Poseidon.sol`; a selector mux
was tried and rejected (30 gas per call for ABIs nobody links to). `--sig` builds other
or multi-selector variants when needed (poseidon-solidity's `hash(uint256[n])`).

## ADR-3 — Modulus at the bottom of the stack, DUPed

PUSH32 F before every MULMOD costs the same 3 gas but 33 bytes: ~17 kB on T4, over
EIP-170 once added to the 33-byte round constants. F is pushed once and reached with
DUPn (stack depth never exceeds 16). Round constants stay PUSH32.

## ADR-4 — Segment DP with an exact-ish scheduler rather than a global search

Atomic A* over stack states explodes (a 15-op segment does not converge in 200 s);
macro moves (pattern-built preparatory shuffle + op) with weighted A* solve a 14-op
T4 partial round in ~5 s and match the unweighted optimum on T3 (137 gas). Cutting
rules matter more than search budget: never inside an S-box, partial-round S-box
glued to the preceding linear layer (F parked under its input, S-box at 42 gas with
no SWAP), full-round linear layers cut per row. A 4× larger budget changed nothing on
T4, so the residual (T4 +11 % over the arithmetic floor, T3 +7 %) is structural.

## ADR-5 — Istanbul-compatible opcodes only

No PUSH0, no MCOPY: 1–2 gas lost per call, deployable unchanged on every L2.
Wrong selector or short calldata revert, matching the Solidity ABI behaviour of the
fork; inputs are reduced implicitly by the first addmod/mulmod, like circomlibjs.

## ADR-6 — Second optimisation pass: what was tried, what is left

Measured against the arithmetic floor (MULMOD/ADD/PUSH/DUPF plus the DUPs forced by
the use counts): T3 partial round 134 gas for a floor of 128, T4 180 for 168.

* Exact (unweighted) search on a single T3 partial round: 134, two SWAPs. Two rounds
  scheduled as one segment: 268, so the segment boundary costs nothing.
* Alternative data flow with the read row taken on the updated lanes
  (X' = Yk + c1·B' + c2·C', constants re-normalised): 146. Rejected.
* Merging the S-box layer of full rounds into one segment, or a full round's rows in
  pairs: identical result on T3; on T4 the two-row segment (6 mulmod, two 5-term sums,
  four inputs used three times each) is intractable for the search. Widening the DP
  (`keep 12`) to let a row park its result under the inputs: −3 gas.
* The two SWAPs per partial round are intrinsic to a stack machine: the lane updates
  consume the old lanes and the old S-box output, and only one of those three can be
  on top of the stack when its turn comes. POP-based variants cost more (DUP+POP = 5
  vs SWAP 3).

Remaining headroom: T3 ≈ 1 % (dispatcher without the calldatasize check −11, MSIZE
for the return length −1), T4 ≈ 2–3 % (last row of full rounds digs the inputs out
from under three results, ≈ 25 gas per round; one SWAP per partial round). Not worth
a new code path against verified artifacts.

No loops anywhere: the runtime is one basic block, every round unrolled with its
constants as PUSH32 and the modulus reached by DUPn. A loop would cost a JUMPI and a
counter per round plus constant loads from code (CODECOPY or a PUSH table) instead of
3 gas per PUSH32, for a smaller runtime that EIP-170 does not require.

## ADR-7 — BLS12-381: own constants pipeline and field-aware lazy reduction

Instances: hadeshash `poseidonperm_x5_255_3` (255/3/8/57, the EF initiative's Poseidon-256) and
255/4/8/56 from the same 2019 script rules (56 for t=4 on 254 and 255 bits; the later script
revision in the daira mirror yields 56 for t=3 too, but circomlib and hadeshash follow the 2019
numbers). Not neptune (R_P=55, sequential Cauchy MDS, domain tag, output lane 1).

The MDS is the Cauchy matrix whose x and y are drawn from the same Grain stream after the round
constants, as the sage script does; this reproduces circomlib bit for bit for t = 3, 4, 5 and
hadeshash's 255/5 constants, and it settles the MDS convention question raised by the Filecoin
spec (whose sequential x, y is neptune's deviation).

Optimised form derived in the column convention (state s, round = M·S(s + c)): constants folded
forward through the actual layers, sparse factorisation backwards (M = B·A, A moved into the
previous round, leftover A into the pre-sparse matrix P), lane 0 of round 0 folded as a constant
S-box, digest row only in the last round, then the diagonal change of basis. Same 510 MULMOD as
the fork on T3; the pipeline regenerates the BN254 numbers within 2 gas.

Lazy reduction is driven by the field: every value carries a bound in units of p and `add` is
used while the sum stays below kmax = floor(2^256 / p) units (5 for BN254, 2 for BLS12-381 Fr).
On BLS the read row of each partial round takes one `addmod` and each lane is reduced every
other round, staggered so all partial rounds share one structure (memoised scheduling). The
final digest combination is an `addmod` so the output is canonical without a `mod`.

The solc-compilable Yul (block-scoped temporaries, in-place S-boxes, 9 live variables) is the
reference in the Foundry tests; the scheduler consumes the flat SSA form (same DAG).
