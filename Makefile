# ZKNOX-Poseidons — build, test, verify and benchmark from the repository root.
#
#   make test      Foundry tests (BN254 + BLS12-381, 10k-run fuzz vs the reference Yul)
#   make verify    Python checks: reference implementation vs circomlib vectors, bytecode vs reference
#   make bench     anvil benchmark, checked against bench/expected.json (make bench-update to refresh)
#   make gen       regenerate yul/ and artifacts/ for the four instances (~15 min, single core)
#   make all       test + verify
#
# Requirements: Foundry (forge, anvil), Python 3.10+ with pycryptodome (`make deps`).
# solc 0.7.6 / 0.8.30 are fetched by forge; set SOLC_FLAGS='--use /path/to/solc' to pin a binary.

FORGE       ?= forge
ANVIL       ?= anvil
PYTHON      ?= python3
SOLC_FLAGS  ?=
BENCH_SOLC  ?=
FUZZ_RUNS   ?= 10000

VECTORS      = test/circomlibjs_vectors.json
YUL_DIR      = yul
ART          = artifacts
BUILD_T3     = --keep 3 --slack 3 --block-max 14 --cut-ops 8 --max-live 7
BUILD_T4     = --weight 1.2 --max-expand 15000 --keep 3 --slack 3 --block-max 20 --cut-ops 8 --max-live 7

.PHONY: help deps build test test-bn254 test-bls verify verify-ref verify-bytecode bench bench-update _bench gen gen-yul gen-bytecode clean all
SHELL := /bin/bash

help:
	@sed -n '2,12p' Makefile | sed 's/^# \{0,1\}//'

deps:
	$(PYTHON) -m pip install -r gen/requirements.txt

build:
	$(FORGE) build $(SOLC_FLAGS)

test: build
	$(FORGE) test $(SOLC_FLAGS) --fuzz-runs $(FUZZ_RUNS) -vv

test-bn254: build
	$(FORGE) test $(SOLC_FLAGS) --fuzz-runs $(FUZZ_RUNS) --match-path test/Poseidon.t.sol -vv

test-bls: build
	$(FORGE) test $(SOLC_FLAGS) --fuzz-runs $(FUZZ_RUNS) --match-path test/PoseidonBLS.t.sol -vv

verify: verify-ref verify-bytecode

# Grain/MDS/permutation against circomlibjs (856 vectors) and hadeshash (255/5 constants)
verify-ref:
	cd gen && $(PYTHON) verify_ref.py ../$(VECTORS)

# generated runtimes against the Python reference (edge cases, unreduced and random inputs)
verify-bytecode:
	cd gen && $(PYTHON) verify.py ../$(ART) ../$(VECTORS)
	cd gen && $(PYTHON) verify_bls.py ../$(ART)/bls12-381

# `make bench` measures and checks every number against bench/expected.json (exit 1 on deviation);
# `make bench-update` rewrites the expected values after an intentional change.
bench: build
	$(MAKE) _bench BENCH_ARGS="--check expected.json"

bench-update: build
	$(MAKE) _bench BENCH_ARGS="--write expected.json"

_bench:
	cd bench && $(FORGE) build $(BENCH_SOLC)
	@$(ANVIL) --silent --gas-limit 400000000 --code-size-limit 100000 & echo $$! > /tmp/anvil.pid; sleep 3; \
	  (cd bench && $(PYTHON) run_bench.py $(BENCH_ARGS) | tee bench_results.txt); status=$${PIPESTATUS[0]}; \
	  kill `cat /tmp/anvil.pid`; exit $$status

# --- regeneration ---------------------------------------------------------------------------
gen: gen-yul gen-bytecode

gen-yul:
	cd gen && $(PYTHON) poseidon_opt.py bn254 3 8 57 PoseidonT3BN254 ../$(YUL_DIR)/PoseidonT3_bn254.sol
	cd gen && $(PYTHON) poseidon_opt.py bn254 4 8 56 PoseidonT4BN254 ../$(YUL_DIR)/PoseidonT4_bn254.sol
	cd gen && $(PYTHON) poseidon_opt.py bls   3 8 57 PoseidonT3BLS   ../$(YUL_DIR)/PoseidonT3_bls12381.sol
	cd gen && $(PYTHON) poseidon_opt.py bls   4 8 56 PoseidonT4BLS   ../$(YUL_DIR)/PoseidonT4_bls12381.sol
	sed 's/library PoseidonT3BLS {/library RefPoseidonT3BLS {/' $(YUL_DIR)/PoseidonT3_bls12381.sol > test/reference/RefPoseidonT3BLS.sol
	sed 's/library PoseidonT4BLS {/library RefPoseidonT4BLS {/' $(YUL_DIR)/PoseidonT4_bls12381.sol > test/reference/RefPoseidonT4BLS.sol

gen-bytecode:
	$(PYTHON) gen/build.py $(YUL_DIR)/PoseidonT3_bn254.flat.sol     --width 3 --name PoseidonT3         --out $(ART)           --memo .memo_bn254_t3.pkl $(BUILD_T3)
	$(PYTHON) gen/build.py $(YUL_DIR)/PoseidonT4_bn254.flat.sol     --width 4 --name PoseidonT4         --out $(ART)           --memo .memo_bn254_t4.pkl $(BUILD_T4)
	$(PYTHON) gen/build.py $(YUL_DIR)/PoseidonT3_bls12381.flat.sol  --width 3 --name PoseidonT3BLS12381 --out $(ART)/bls12-381 --memo .memo_bls_t3.pkl   $(BUILD_T3)
	$(PYTHON) gen/build.py $(YUL_DIR)/PoseidonT4_bls12381.flat.sol  --width 4 --name PoseidonT4BLS12381 --out $(ART)/bls12-381 --memo .memo_bls_t4.pkl   $(BUILD_T4)
	cp $(ART)/src/PoseidonT3.sol $(ART)/src/PoseidonT4.sol $(ART)/bls12-381/src/PoseidonT3BLS12381.sol $(ART)/bls12-381/src/PoseidonT4BLS12381.sol src/

clean:
	rm -rf out cache bench/out bench/cache gen/__pycache__ .memo_*.pkl

all: test verify
