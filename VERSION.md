# Changelog

## 0.3.3 — 2026-09-10

* Repository renamed ZKNOX-Poseidons; README states the BLS12-381 / Bandersnatch migration
  scope and adds the references (Guillevic–Masson CiC 2026, Bandersnatch ePrint 2021/1152,
  Poseidon, Poseidon2, EF initiative, Filecoin spec).

## 0.3.2 — 2026-09-10

* README: gas budget of the shielded pool's simplest transaction (shield = 16 T3 + 1 T4); provenance of
  the shielded pool's current Poseidon (circomlibjs `createCode` injected by `tasks/overrides.ts`, circomlib
  `Poseidon(2)`/`Poseidon(3)` in circuits-v2); `bench/check_shielded_mainnet.sh` and the mainnet
  library addresses it found (0xf5fe…2563 T3, 0xafd3…abd3 T4, circomlibjs runtimes).

* Gas comparison extended to platus-xyz/poseidon2-solidity (Poseidon2 t=4 sponge on BN254,
  17,143 warm for 2 words vs 10,521 here) in `make bench`; 60 checked numbers.
* `artifacts/poseidon-solidity-abi/`, `src/PoseidonT{3,4}ForkAbi.sol`: builds serving the fork's
  `hash(uint256[n])` selectors; `test/PoseidonForkAbi.t.sol` proves I/O and ABI compatibility
  with partylikeits1983/poseidon-solidity (10k-run fuzz, edge and regression vectors).

## 0.3.1 — 2026-09-10

* `make bench` checks the 50 measured numbers (single hash cold/warm, insertLeaves, runtime
  sizes, both fields) against `bench/expected.json` and fails on deviation; `make bench-update`.

* Repository layout: Makefile (`test`, `verify`, `bench`, `gen`), `.gitignore`, MIT license,
  GitHub Actions workflow, `gen/requirements.txt`, `gen/verify_ref.py`, `gen/verify_bls.py`.
* BN254 artifacts regenerated from the repository's own constants pipeline (10,149 / 14,051
  gas in the callee, circomlib hashes) so `make gen` reproduces `artifacts/` without the
  poseidon-solidity fork, which stays in `test/reference/` as an external cross-check.

## 0.3.0 — 2026-09-10

* `gen/poseidon_opt.py`: optimised-circuit derivation from any reference instance (constant
  folding, sparse factorisation, diagonal normalisation) and Yul emission with field-aware lazy
  reduction (kmax summands per 256-bit add); block-scoped form for solc, flat form for the
  scheduler; every step checked against `poseidon_ref.py`.
* BLS12-381 Fr instances 255/3/8/57 and 255/4/8/56: bytecode 11,368 / 16,008 gas in the callee
  (11,740 / 16,383 warm on anvil), 13,952 / 20,045-byte runtimes; solc-compiled Yul baseline
  13,637 / 18,485 warm. `artifacts/bls12-381/`, `src/PoseidonT{3,4}BLS12381.sol`.
* BN254 regenerated from the same pipeline: 10,149 / 14,051 gas, circomlib hashes (delivered
  artifacts unchanged).
* Tests: `test/PoseidonBLS.t.sol` (11 tests, 10k-run fuzz vs the solc-compiled generated Yul);
  bench extended to both fields; pipeline now field-agnostic (modulus read from the DAG).

## 0.1.1 — 2026-09-10

* Second optimisation pass (ADR-6): no bytecode change; documents what was tried
  (updated-lane data flow, merged S-box layers, two-row segments, wider DP) and the
  remaining headroom (T3 ≈ 1 %, T4 ≈ 2–3 %).
* Scheduler: a sum grows one term at a time (single partial per sum node), same results,
  ~2× faster search; `--min-ops` cut option.

## 0.1.0 — 2026-09-09

* Generator `gen/` (yuldag, segment, canon, sched, build, analyze): re-schedules the
  poseidon-solidity Yul into optimal straight-line EVM bytecode.
* PoseidonT3: 10,150 gas in the callee (10,522 warm STATICCALL on anvil), 13,731-byte
  runtime; poseidon-solidity fork: 12,776 warm, 14,660 bytes. −17.6 % warm, −19 % callee.
* PoseidonT4: 14,049 gas in the callee (14,424 warm), 19,750-byte runtime; fork:
  16,812 warm, 20,748 bytes. −14.2 % warm, −15 % callee.
* ABI: exactly the shielded pool's `poseidon(bytes32[n]) returns (bytes32)` (iden3 signature), one
  selector, no dispatcher mux; `--sig` (repeatable) builds other or multi-selector variants.
* the shielded pool `Commitments.insertLeaves` (depth 16), called through `poseidon(bytes32[2])`:
  349,559 gas for one leaf vs 385,623 (fork) and 651,191 (iden3, deployed today);
  roots identical.
* `src/PoseidonT{3,4}.sol`: constructor-returns-runtime contracts (solc 0.7.6..0.8.x),
  `IPoseidonT{3,4}` interfaces; `artifacts/` with runtime/creation hex and JSON metadata.
* Tests: 13 Foundry tests incl. 10k-run fuzz equality with the fork's Yul; anvil bench;
  428 circomlibjs vectors replayed through the runtime.

## 0.2.0 — 2026-09-10

* `gen/poseidon_ref.py`: reference Poseidon in Python (Grain-LFSR round constants, Cauchy MDS
  with x, y drawn from the same Grain stream, permutation, circomlib-style hash), CLI
  `python3 gen/poseidon_ref.py <p> <n> <t> <R_F> <R_P>`.
* Validated on BN254: round constants and MDS identical to circomlib for t = 3, 4, 5
  (254/3/8/57, 254/4/8/56, 254/5/8/60); 428 + 428 circomlibjs hash vectors, 0 mismatches.
* Validated on BLS12-381 Fr: round constants and MDS identical to hadeshash
  `poseidonperm_x5_255_5` (255/5/8/60, via the copy shipped in ingonyama's poseidon-hash),
  permutation output identical to that implementation.
* `params/`: generated instances with test vectors, including the EF initiative's
  Poseidon-256 instance `poseidon_bls12381_255_3_8_57.json` (hadeshash
  `poseidonperm_x5_255_3`), plus 255/5/8/60 and the circomlib 254/3/8/57 for reference.
