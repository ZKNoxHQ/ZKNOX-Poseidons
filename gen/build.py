"""Re-schedule a poseidon-solidity Yul body into hand-optimal straight-line EVM bytecode.

    python3 gen/build.py ../poseidon-solidity/src/PoseidonT3.sol --width 3 --out artifacts
    python3 gen/build.py ../poseidon-solidity/src/PoseidonT4.sol --width 4 --out artifacts \
        --weight 1.2 --max-expand 40000 --block-max 16 --max-live 5

Outputs, per library: <Name>.runtime.hex, <Name>.creation.hex, <Name>.json
(selector, sizes, exact gas), and src/<Name>.sol (constructor returns the runtime).
"""
import argparse
import json
import re
import os
import pickle
import sys
import time

from yuldag import parse_library, MODULUS
from segment import segments
from canon import Canon
from sched import Solver, F, OPGAS, PUSH_COST

OPCODE = {"add": 0x01, "mulmod": 0x09, "addmod": 0x08}


# ---------------------------------------------------------------------------
def plan(dag, stmts, width, slack=6, keep=6, max_live=6, cut_ops=8, block_max=12,
         max_expand=200000, weight=1.0, memo_path=None, verbose=True, min_ops=1):
    """DP over stack orders at segment boundaries. Returns (chain, body_gas)."""
    segs, comp = segments(dag, stmts, width, min_ops, block_max, max_live=max_live, cut_ops=cut_ops,
                          no_cut_before_sbox=True)
    if verbose:
        print(f"{len(segs)} segments", file=sys.stderr)
    memo = pickle.load(open(memo_path, "rb")) if memo_path and os.path.exists(memo_path) else {}
    dp = {(): 0}
    back = []
    t0 = time.time()
    for si, seg in enumerate(segs):
        s0, s1, live_in, live_out = seg
        ndp, nback = {}, {}
        bestin = min(dp.values())
        for in_order, gin in dp.items():
            if gin > bestin + keep:
                continue
            cn = Canon(dag, comp, seg, in_order, tuple(live_out))
            key = cn.seg.key
            if key not in memo:
                found, _ = Solver(cn.seg).solve(slack=slack, want_all_orders=True,
                                                max_expand=max_expand, weight=weight)
                memo[key] = found
                if memo_path:
                    pickle.dump(memo, open(memo_path + ".tmp", "wb"))
                    os.replace(memo_path + ".tmp", memo_path)
            for canon_out, (cost, prog) in memo[key].items():
                out_order = tuple(cn.actual[c] for c in canon_out)
                tot = gin + cost
                if tot < ndp.get(out_order, 1 << 60):
                    ndp[out_order] = tot
                    nback[out_order] = (in_order, cn, canon_out, prog, cost)
        if not ndp:
            raise RuntimeError(f"segment {si} ({s0}-{s1}) unsolvable from any input order")
        dp = ndp
        back.append(nback)
        if verbose and (si % 5 == 0 or si == len(segs) - 1):
            print(f"  seg {si:3d} stmts {s0}-{s1} live {len(live_in)}->{len(live_out)} "
                  f"best {min(dp.values())} memo {len(memo)} t={time.time() - t0:.1f}s", file=sys.stderr)
    out_order = min(dp, key=dp.get)
    total = dp[out_order]
    chain = []
    for si in range(len(segs) - 1, -1, -1):
        in_order, cn, canon_out, prog, cost = back[si][out_order]
        chain.append((cn, canon_out, prog, cost))
        out_order = in_order
    chain.reverse()
    return chain, total


# ---------------------------------------------------------------------------
def push_bytes(v):
    if v == 0:
        return bytes([0x60, 0])
    b = v.to_bytes((v.bit_length() + 7) // 8, "big")
    return bytes([0x5F + len(b)]) + b


def emit(chain, dag, selectors, width):
    """Runtime bytecode: dispatcher (any of `selectors`), modulus, scheduled segments, return."""
    code = bytearray()
    need = 4 + 32 * (width - 1)
    code += push_bytes(0) + bytes([0x35])                     # calldataload(0)
    code += push_bytes(0xE0) + bytes([0x1C])                  # shr(0xe0, .) -> sel
    if len(selectors) == 1:
        code += push_bytes(selectors[0]) + bytes([0x18])      # xor -> 0 iff selector matches
    else:
        # bad = iszero(eq(sel, s1) | eq(sel, s2) | ...)
        for i, s in enumerate(selectors):
            last = i == len(selectors) - 1
            if not last:
                code += bytes([0x80])                         # dup1
            code += push_bytes(s) + bytes([0x14])             # eq  -> flag on top
            if not last:
                code += bytes([0x90])                         # swap1: sel back on top, flag below
        # stack (top first): flag_last, flag_{n-2}, ..., flag_0
        code += bytes([0x17]) * (len(selectors) - 1)          # or ... or
        code += bytes([0x15])                                 # iszero -> bad selector
    code += push_bytes(need) + bytes([0x36, 0x10])            # lt(calldatasize, need)
    code += bytes([0x17])                                     # or
    jpos = len(code)
    code += bytes([0x61, 0, 0, 0x57])                         # push2 <revert>; jumpi
    code += push_bytes(dag.modulus)                           # F stays at the bottom of the stack
    stack = [F]
    body_gas = 0
    for cn, canon_out, prog, cost in chain:
        stack = [F] + list(range(len(stack) - 1))
        seg_gas = 0
        for ins in prog:
            op = ins[0]
            if op == "PUSH":
                node = dag.nodes[cn.actual[ins[1]]]
                if node.kind == "const":
                    code += push_bytes(node.val)
                    seg_gas += 3
                else:
                    code += push_bytes(node.val) + bytes([0x35])
                    seg_gas += 6
                stack.append(ins[1])
            elif op == "DUPF":
                n = len(stack)
                assert stack[0] == F and n <= 16, stack
                code += bytes([0x7F + n])
                stack.append(F)
                seg_gas += 3
            elif op == "DUP":
                n = ins[1]
                assert 1 <= n <= 16
                code += bytes([0x7F + n])
                stack.append(stack[-n])
                seg_gas += 3
            elif op == "SWAP":
                n = ins[1]
                assert 1 <= n <= 16
                code += bytes([0x8F + n])
                stack[-1], stack[-1 - n] = stack[-1 - n], stack[-1]
                seg_gas += 3
            elif op == "OP":
                kind, o = ins[1], ins[2]
                code += bytes([OPCODE[kind]])
                seg_gas += OPGAS[kind]
                if kind == "add":
                    a, b = stack.pop(), stack.pop()
                    ma = a[2] if type(a) is tuple else cn.seg.term_bit[o][a]
                    mb = b[2] if type(b) is tuple else cn.seg.term_bit[o][b]
                    m = ma | mb
                    stack.append(o if m == (1 << len(cn.args[o])) - 1 else ("S", o, m))
                else:
                    a, b, f = stack.pop(), stack.pop(), stack.pop()
                    assert f == F and ({a, b} == set(cn.args[o]) or (a == b == cn.args[o][0]))
                    stack.append(o)
        assert stack[0] == F and tuple(stack[1:]) == tuple(canon_out), (stack, canon_out)
        assert seg_gas == cost, (seg_gas, cost)
        body_gas += seg_gas
    assert len(stack) == 2, stack
    code += push_bytes(0) + bytes([0x52])                     # mstore(0, out)
    code += push_bytes(0x20) + push_bytes(0) + bytes([0xF3])  # return(0, 32)
    rdest = len(code)
    code += bytes([0x5B]) + push_bytes(0) + push_bytes(0) + bytes([0xFD])
    code[jpos + 1:jpos + 3] = rdest.to_bytes(2, "big")
    return bytes(code), body_gas


def creation_code(runtime):
    """Minimal 12-byte deployer: PUSH2 len DUP1 PUSH1 12 PUSH1 0 CODECOPY PUSH1 0 RETURN."""
    n = len(runtime)
    return bytes([0x61]) + n.to_bytes(2, "big") + bytes([0x80, 0x60, 0x0C, 0x60, 0x00, 0x39, 0x60, 0x00, 0xF3]) + runtime


# ---------------------------------------------------------------------------
# minimal EVM for the generated code (exact gas, straight-line + dispatcher)
GAS = {0x01: 3, 0x08: 8, 0x09: 8, 0x10: 3, 0x14: 3, 0x15: 3, 0x17: 3, 0x18: 3, 0x1C: 3, 0x35: 3, 0x36: 2, 0x50: 2, 0x52: 3,
       0x56: 8, 0x57: 10, 0x5B: 1, 0x5F: 2, 0xF3: 0, 0xFD: 0}


def run(code, calldata):
    pc, gas, st, mem = 0, 0, [], bytearray(64)
    M = 1 << 256
    while True:
        op = code[pc]
        if 0x60 <= op <= 0x7F:
            n = op - 0x5F
            st.append(int.from_bytes(code[pc + 1:pc + 1 + n], "big"))
            pc += 1 + n
            gas += 3
            continue
        gas += GAS.get(op, 3)
        if 0x80 <= op <= 0x8F:
            st.append(st[-(op - 0x7F)])
        elif 0x90 <= op <= 0x9F:
            n = op - 0x8F
            st[-1], st[-1 - n] = st[-1 - n], st[-1]
        elif op == 0x01:
            st.append((st.pop() + st.pop()) % M)
        elif op == 0x08:
            a, b, n = st.pop(), st.pop(), st.pop()
            st.append((a + b) % n if n else 0)
        elif op == 0x09:
            a, b, n = st.pop(), st.pop(), st.pop()
            st.append((a * b) % n if n else 0)
        elif op == 0x10:
            a, b = st.pop(), st.pop()
            st.append(1 if a < b else 0)
        elif op == 0x14:
            st.append(1 if st.pop() == st.pop() else 0)
        elif op == 0x15:
            st.append(1 if st.pop() == 0 else 0)
        elif op == 0x17:
            st.append(st.pop() | st.pop())
        elif op == 0x18:
            st.append(st.pop() ^ st.pop())
        elif op == 0x1C:
            a, b = st.pop(), st.pop()
            st.append(b >> a)
        elif op == 0x35:
            off = st.pop()
            d = calldata[off:off + 32] + b"\0" * 32
            st.append(int.from_bytes(d[:32], "big"))
        elif op == 0x36:
            st.append(len(calldata))
        elif op == 0x50:
            st.pop()
        elif op == 0x52:
            off, v = st.pop(), st.pop()
            mem[off:off + 32] = v.to_bytes(32, "big")
        elif op == 0x57:
            dest, cond = st.pop(), st.pop()
            if cond:
                pc = dest
                assert code[pc] == 0x5B
                continue
        elif op == 0x5B:
            pass
        elif op == 0xF3:
            off, size = st.pop(), st.pop()
            return bytes(mem[off:off + size]), gas
        elif op == 0xFD:
            return None, gas
        else:
            raise ValueError(f"unsupported opcode {op:#x}")
        pc += 1


def selector_of(sig):
    from Crypto.Hash import keccak
    h = keccak.new(digest_bits=256)
    h.update(sig.encode())
    return int.from_bytes(h.digest()[:4], "big")


SOL_TEMPLATE = '''// SPDX-License-Identifier: MIT
pragma solidity >=0.7.6 <0.9.0;

/// @title Circomlib-compatible Poseidon hash, width {width} ({ninputs} inputs), BN254 scalar field
/// @notice Generated by gen/build.py from poseidon-solidity's PoseidonT{width}.sol (same permutation,
///         same constants); the arithmetic is re-scheduled as hand-optimal straight-line EVM code.
///         Deploying this contract installs that runtime, which answers to {sigs}
///         (selectors {selectors}) and reduces each input modulo the field like circomlibjs.
///         Runtime: {rtsize} bytes, {gas} gas per call inside the callee (data-independent).
contract {name} {{
    bytes internal constant RUNTIME =
        hex"{runtime}";

    constructor() {{
        bytes memory code = RUNTIME;
        assembly {{
            return(add(code, 0x20), mload(code))
        }}
    }}
}}

interface I{name} {{
{functions}}}
'''


def interface_functions(sigs):
    out = []
    for sig in sigs:
        m = re.fullmatch(r"(\w+)\((uint256|bytes32)\[(\d+)\]\)", sig)
        assert m, f"unsupported signature {sig}"
        name, typ, n = m.groups()
        out.append(f"    function {name}({typ}[{n}] calldata inputs) external pure returns ({typ});\n")
    return "".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("source", help="poseidon-solidity PoseidonT<w>.sol (Yul body is parsed)")
    ap.add_argument("--width", type=int, required=True)
    ap.add_argument("--name", default=None)
    ap.add_argument("--sig", action="append", default=None,
                    help="ABI signature accepted by the dispatcher (repeatable; several selectors cost "
                         "~15 gas each). Default: poseidon(bytes32[n]) with n = width-1, i.e. the "
                         "iden3/circomlibjs signature the shielded pool's library stub links to")
    ap.add_argument("--out", default="artifacts")
    ap.add_argument("--slack", type=int, default=6)
    ap.add_argument("--keep", type=int, default=6)
    ap.add_argument("--max-live", type=int, default=6)
    ap.add_argument("--cut-ops", type=int, default=8)
    ap.add_argument("--block-max", type=int, default=12)
    ap.add_argument("--min-ops", type=int, default=1, help="minimum op nodes before a natural cut")
    ap.add_argument("--max-expand", type=int, default=200000)
    ap.add_argument("--weight", type=float, default=1.0)
    ap.add_argument("--memo", default=None, help="pickle file to checkpoint segment solutions")
    args = ap.parse_args()
    width = args.width
    name = args.name or f"PoseidonT{width}"
    sigs = args.sig or [f"poseidon(bytes32[{width - 1}])"]
    sels = [selector_of(x) for x in sigs]
    sel = sels[0]

    dag, stmts = parse_library(args.source)
    chain, body = plan(dag, stmts, width, slack=args.slack, keep=args.keep, max_live=args.max_live,
                       cut_ops=args.cut_ops, block_max=args.block_max, max_expand=args.max_expand,
                       weight=args.weight, memo_path=args.memo, min_ops=args.min_ops)
    runtime, body_gas = emit(chain, dag, sels, width)
    assert body_gas == body
    creation = creation_code(runtime)
    # self-check: run the reference vector (1, 2, ...) through the mini EVM
    outs = set()
    for sx in sels:
        cd = sx.to_bytes(4, "big") + b"".join(i.to_bytes(32, "big") for i in range(1, width))
        out, gas = run(runtime, cd)
        outs.add(out)
    assert len(outs) == 1 and out is not None, "dispatcher self-check failed"
    os.makedirs(args.out, exist_ok=True)
    os.makedirs(os.path.join(args.out, "src"), exist_ok=True)
    open(os.path.join(args.out, f"{name}.runtime.hex"), "w").write("0x" + runtime.hex() + "\n")
    open(os.path.join(args.out, f"{name}.creation.hex"), "w").write("0x" + creation.hex() + "\n")
    info = {"name": name, "width": width, "signatures": sigs, "selectors": [f"{x:#010x}" for x in sels],
            "runtime_bytes": len(runtime), "creation_bytes": len(creation), "callee_gas": gas,
            "body_gas": body_gas, "sample_input": list(range(1, width)), "sample_output": f"{int.from_bytes(out, 'big'):#066x}"}
    json.dump(info, open(os.path.join(args.out, f"{name}.json"), "w"), indent=2)
    open(os.path.join(args.out, "src", f"{name}.sol"), "w").write(SOL_TEMPLATE.format(
        width=width, ninputs=width - 1, sigs=", ".join(f"`{x}`" for x in sigs),
        selectors=", ".join(f"{x:#010x}" for x in sels), rtsize=len(runtime), gas=gas,
        name=name, runtime=runtime.hex(), functions=interface_functions(sigs)))
    print(json.dumps(info, indent=2))


if __name__ == "__main__":
    main()
