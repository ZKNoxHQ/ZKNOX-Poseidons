# ZKNOX-Poseidons

Hand-scheduled Poseidon hash bytecode for the EVM, over BN254 (circomlib instances, drop-in
for the shielded pools' iden3 bytecode) and over the BLS12-381 scalar field (hadeshash instances, the EF
Poseidon Cryptanalysis Initiative's Poseidon-256 for t=3), with the generator that produces it
and the tests that pin it to the references.

This repository is a prelude to the migration from BN254 to BLS12-381 and Bandersnatch: the
BLS12-381 scalar field is the base field of Bandersnatch, so the same Poseidon instances serve
a Merkle tree, a note commitment and a key derivation living on Bandersnatch, verified on
Ethereum through the EIP-2537 BLS12-381 precompiles. The BN254 artifacts are the drop-in step
for today's deployments; the BLS12-381 ones are the target field's.

Naming, as in circomlib: **PoseidonT3** is the width-3 permutation hashing **2 inputs**
(Merkle node), **PoseidonT4** the width-4 permutation hashing **3 inputs** (note commitment).

| gas per hash, anvil, warm STATICCALL | 2 inputs (T3) | 3 inputs (T4) |
|---|---|---|
| iden3 / circomlibjs `createCode` bytecode (what shielded pools link today) | 29,374 | 45,500 |
| [partylikeits1983/poseidon-solidity](https://github.com/partylikeits1983/poseidon-solidity) (Yul, solc 0.7.6) | 12,776 | 16,812 |
| [platus-xyz/poseidon2-solidity](https://github.com/platus-xyz/poseidon2-solidity) (Poseidon2, width-4 sponge, packed calldata) | 17,143 | 17,146 |
| **ZKNOX-Poseidons, BN254** | **10,521** | **14,426** |
| ZKNOX-Poseidons, BLS12-381 | 11,740 | 16,383 |

Cold calls: +2,509 on every entry (first touch of the account). Inside the callee,
data-independent: BN254 10,149 (T3) / 14,051 (T4), BLS12-381 11,368 / 16,008.

| shielded pool `Commitments.insertLeaves(1)`, depth 16 = 16 two-input hashes + tree bookkeeping | gas |
|---|---|
| iden3 / circomlibjs | 651,191 |
| poseidon-solidity | 385,623 |
| platus Poseidon2 (its own roots) | 455,111 |
| **ZKNOX-Poseidons, BN254** | **349,543** |
| ZKNOX-Poseidons, BLS12-381 | 369,047 |

Runtime sizes (T3 / T4): poseidon-solidity 14,660 / 20,748 B, platus 15,095 B (one contract),
ZKNOX-Poseidons 13,731 / 19,750 B (BN254), 13,952 / 20,045 B (BLS12-381).

`make bench` re-measures everything on anvil (the two other repos are compiled at their own
settings: poseidon-solidity solc 0.7.6 legacy optimizer, platus solc 0.8.27 runs 20000 cancun,
bytecodes in `bench/gen/`) and checks the 59 numbers against `bench/expected.json`, failing on
any deviation; `make bench-update` refreshes that file after an intentional change.

### What it means for the simplest shielded transaction

A shield (deposit) is the cheapest shielded transaction that touches Poseidon: one commitment
`hashCommitment(npk, tokenID, value)` = one 3-input hash (T4), then `insertLeaves` of that one
leaf = sixteen 2-input hashes (T3, one `hashLeftRight` per level of the depth-16 tree). Both
libraries are touched cold once (+2,509 each). With the warm numbers above:

| hash part of a shield = 16 × T3 + 1 × T4 + 2 cold touches | gas | vs iden3 | vs poseidon-solidity |
|---|---|---|---|
| iden3 / circomlibjs (the shielded pools' current bytecode) | 520,502 | | |
| poseidon-solidity | 226,246 | −294,256 | |
| **ZKNOX-Poseidons, BN254** | **187,780** | **−332,722 (−64 %)** | **−38,466 (−17 %)** |
| ZKNOX-Poseidons, BLS12-381 | 209,241 | −311,261 | |

The rest of the shield (token transfer, tree bookkeeping, event) is unchanged; the measured
`insertLeaves(1)` figures (651,191 / 385,623 / 349,543) confirm the same deltas end to end,
the ~181 k left in that call being cold SSTOREs of the fresh tree. A private transfer inserts
two commitments (16 T3 again) and adds the SNARK verification, so its hash part moves by the
same 16 × 18,853 ≈ 302 k vs iden3.

### I/O compatibility with poseidon-solidity (BN254)

Same function: circomlib Poseidon, inputs reduced modulo p (any `uint256`, not only canonical
ones), canonical digest. `test/PoseidonForkAbi.t.sol` deploys the fork's own library next to
the `hash(uint256[n])` builds of our runtimes (`artifacts/poseidon-solidity-abi/`,
`src/PoseidonT{3,4}ForkAbi.sol`, selectors `0x561558fe` / `0x20cf0a37`, same calldata layout)
and checks equality of the digests on 10,000 fuzzed inputs per width, on the edge cases
(0, p−1, p, p+1, 2²⁵⁶−1, 2²⁵⁵), on circomlib's vector and on the fork's own lazy-reduction
regression vector, plus the identity between the `hash(uint256[n])` and `poseidon(bytes32[n])`
builds. `test/Poseidon.t.sol` does the same through the shielded-pool ABI. The fork-ABI build costs
the same gas (10,149 / 14,051 in the callee); only the selector differs.

## Quick start

```
make deps      # python: pycryptodome
make test      # Foundry: 31 tests, 10k-run fuzz equality with poseidon-solidity and the reference Yul, vectors, gas, EIP-170
make verify    # Python: Grain/MDS vs circomlib and hadeshash, runtimes vs the reference on 1,670 inputs
make bench     # anvil benchmark, every number checked against bench/expected.json (exit 1 on deviation)
make gen       # regenerate yul/ and artifacts/ from the reference constants (~15 min, one core)
```

Requirements: [Foundry](https://getfoundry.sh) (forge, anvil; solc 0.7.6 and 0.8.30 are fetched
automatically, or pin binaries with `SOLC_FLAGS='--use /path/solc-0.7.6'` and
`BENCH_SOLC='--use /path/solc-0.8.30'`), Python 3.10+. Node and circomlibjs are only needed to
regenerate `test/circomlibjs_vectors.json` and `bench/gen/iden3_T*.hex` (`bench/gen/*.js`).

## Instances

| artifact | field | t / R_F / R_P | source | ABI |
|---|---|---|---|---|
| `PoseidonT3` | BN254 | 3 / 8 / 57 | circomlib = hadeshash `poseidonperm_x5_254_3` | `poseidon(bytes32[2])` `0x299e5660` |
| `PoseidonT4` | BN254 | 4 / 8 / 56 | circomlib | `poseidon(bytes32[3])` `0x5a53025d` |
| `PoseidonT3BLS12381` | BLS12-381 Fr | 3 / 8 / 57 | hadeshash `poseidonperm_x5_255_3` (EF Poseidon-256) | `poseidon(bytes32[2])` |
| `PoseidonT4BLS12381` | BLS12-381 Fr | 4 / 8 / 56 | same script rules | `poseidon(bytes32[3])` |

All four: circomlib conventions (capacity 0 in lane 0, digest lane 0), inputs reduced modulo
the field like circomlibjs, any other selector or short calldata reverts. Constants and
matrices are in `params/` with test vectors. Other ABIs: `gen/build.py --sig` (repeatable).

### Using the artifacts

* Foundry: `import "ZKNOX-Poseidons/src/PoseidonT3.sol"; address h = address(new PoseidonT3());`
  then `IPoseidonT3(h).poseidon([a, b])`. The constructor returns the generated runtime, so
  `type(PoseidonT3).creationCode` deploys it like any contract.
* Raw: `artifacts/<Name>.creation.hex` is a 12-byte deployer plus the runtime, the same shape as
  `poseidonContract.createCode(n)` from circomlibjs. A shielded pool's deploy task can deploy it
  in place of the iden3 bytecode and link the address into its existing
  `library PoseidonT3 { function poseidon(bytes32[2] memory) public pure returns (bytes32) {} }`
  stub; nothing changes in `Poseidon.sol` or the callers.

`bench/check_shielded_mainnet.sh` (needs `cast` and a mainnet RPC in `RPC=`) reads the implementation
behind the shielded pool's proxy, extracts its linked library addresses and matches their code
against the circomlibjs and ZKNOX-Poseidons runtimes.

## Layout

```
Makefile           test / verify / bench / gen from the root
src/               constructor-returns-runtime contracts + interfaces (BN254 and BLS12-381)
artifacts/         runtime.hex, creation.hex, json (selector, sizes, exact gas); bls12-381/ and
                   poseidon-solidity-abi/ (hash(uint256[n]) selector) subfolders
yul/               generated optimised Yul: block-scoped (solc-compilable reference), .flat.sol (scheduler input)
params/            reference instances: Grain constants, MDS x/y, test vectors
gen/               generator (Python)
  poseidon_ref.py    Grain LFSR, Cauchy MDS, reference permutation and hash
  poseidon_opt.py    constant folding, sparse factorisation, diagonal normalisation, Yul emission
  yuldag.py, segment.py, canon.py, sched.py, build.py   Yul -> DAG -> scheduled straight-line bytecode
  verify*.py, analyze.py
test/              Foundry tests; test/reference/ holds the solc-compiled references
                   (poseidon-solidity's Yul for BN254, the generated Yul for BLS12-381)
bench/             anvil harness: single hash cold/warm, shielded pool Commitments.insertLeaves; iden3, poseidon-solidity
                   and platus Poseidon2 bytecodes; expected.json
```

## What the generator does

1. `poseidon_ref.py` reproduces hadeshash's `generate_parameters_grain.sage`: Grain-LFSR round
   constants and the Cauchy MDS whose x and y are drawn from the same stream. It matches
   circomlib bit for bit for t = 3, 4, 5 on BN254 and hadeshash's 255/5 constants on BLS12-381.
2. `poseidon_opt.py` derives the optimised circuit (partial-round constants folded into lane 0,
   partial-round MDS factored into sparse layers with a pre-sparse matrix, capacity S-box of
   round 0 folded, digest row only in the last round), applies the diagonal change of basis
   (one coefficient per free row becomes 1, S-box inputs may be scaled since (λx)⁵ = λ⁵x⁵) and
   emits Yul with lazy reduction driven by the field: `add` while the sum stays under
   floor(2²⁵⁶/p) field-sized summands (5 on BN254, 2 on BLS12-381), `addmod` otherwise.
   Every step is checked against the reference with exact and then 256-bit semantics.
3. `build.py` parses the flat Yul into a DAG, cuts it into small segments (never inside an
   S-box, partial rounds kept whole), schedules each segment optimally on the EVM stack
   (macro-move search, weighted A*) with a DP over stack orders at segment boundaries, and
   emits one basic block: dispatcher, modulus at the bottom of the stack (DUPn), 510 MULMOD for
   T3, constants as PUSH32, return. No loops, no memory but the return word, constant gas.

Where the gas goes (T3, BN254): 510 MULMOD = 4,080 gas; solc spends 5,970 gas in 1,406 DUP +
352 SWAP + 349 POP on the same arithmetic, the scheduled code 21 DUP and 2 SWAP per partial
round (134 gas, arithmetic floor 128). Remaining headroom about 1 % on T3, 2–3 % on T4
(DECISIONS.md ADR-6). BLS12-381 pays only the extra `addmod` (T3: 140 vs 27).

## Verification

* Foundry (`make test`, 31 tests): circomlib and hadeshash vectors, poseidon-solidity's T4
  lazy-reduction regression vector, `hash(x) == hash(x mod p)`, 10,000-run fuzz equality with the
  solc-compiled reference Yul for each of the four instances and with poseidon-solidity's library
  through its own ABI, selector and calldata rejection, gas bounds, EIP-170.
* Python (`make verify`): Grain constants and MDS against circomlib (t = 3, 4, 5) and hadeshash
  (255/5); 856 circomlibjs hash vectors; each runtime replayed in a small EVM interpreter on
  edge, unreduced and random inputs with exact gas.
* anvil (`make bench`): 305 vectors identical across iden3, poseidon-solidity and this bytecode
  per field, identical Merkle roots in `insertLeaves`.

License: MIT (LICENSE). See DECISIONS.md for the design record (why raw bytecode, modulus on the stack, segmentation,
what was tried and rejected, the BLS12-381 conventions) and VERSION.md for the changelog.

## References

* Aurore Guillevic and Simon Masson, *Embedded Elliptic Curves and Embedded Families for
  SNARK-Friendly Elliptic Curves*, IACR Communications in Cryptology, vol. 3, no. 2, Aug 03, 2026,
  doi: [10.62056/a33zl83y6](https://doi.org/10.62056/a33zl83y6), <https://cic.iacr.org/p/3/2/12>.
* Simon Masson, Antonio Sanso and Zhenfei Zhang, *Bandersnatch: a fast elliptic curve built over
  the BLS12-381 scalar field*, IACR ePrint 2021/1152, <https://eprint.iacr.org/2021/1152>.
* Lorenzo Grassi, Dmitry Khovratovich, Christian Rechberger, Arnab Roy and Markus Schofnegger,
  *Poseidon: A New Hash Function for Zero-Knowledge Proof Systems*, USENIX Security 2021,
  IACR ePrint 2019/458; reference implementation and instances: <https://extgit.isec.tugraz.at/krypto/hadeshash>.
* Lorenzo Grassi, Dmitry Khovratovich and Markus Schofnegger, *Poseidon2: A Faster Version of the
  Poseidon Hash Function*, AFRICACRYPT 2023, IACR ePrint 2023/323.
* Ethereum Foundation, *Poseidon Cryptanalysis Initiative*, <https://www.poseidon-initiative.info/>
  (Poseidon-256: BLS12-381 scalar field, d = 5, t = 3).
* Filecoin, *Poseidon hash specification* (neptune conventions), filecoin-project/specs.
* iden3, circomlib and circomlibjs (BN254 constants and the `createCode` EVM generator);
  partylikeits1983/poseidon-solidity; platus-xyz/poseidon2-solidity; the shielded pool's
  contract and circuits repositories.
