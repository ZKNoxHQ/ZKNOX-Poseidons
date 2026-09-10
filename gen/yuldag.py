"""Parse the straight-line Yul body of a poseidon-solidity library into a hash-consed DAG."""
import re

MODULUS = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001


class Node:
    __slots__ = ("id", "kind", "args", "val", "users")

    def __init__(self, id, kind, args=(), val=None):
        self.id, self.kind, self.args, self.val = id, kind, tuple(args), val
        self.users = []  # consumer node ids (one entry per operand slot)

    def __repr__(self):
        if self.kind == "const":
            return f"K{self.id}({hex(self.val)[:10]})"
        if self.kind == "calldataload":
            return f"CD{self.id}({hex(self.val)})"
        return f"{self.kind}{self.id}{self.args}"


class DAG:
    def __init__(self):
        self.nodes = []
        self.memo = {}

    def node(self, kind, args=(), val=None):
        key = (kind, tuple(args), val)
        if kind in ("const", "calldataload"):
            key = (kind, (), val)
        if key in self.memo:
            return self.memo[key]
        n = Node(len(self.nodes), kind, args, val)
        self.nodes.append(n)
        self.memo[key] = n.id
        for a in args:
            self.nodes[a].users.append(n.id)
        return n.id


TOKEN = re.compile(r"\s*(0x[0-9a-fA-F]+|[0-9]+|[A-Za-z_][A-Za-z_0-9]*|:=|[(),{}])")


def tokenize(src):
    pos, out = 0, []
    while pos < len(src):
        m = TOKEN.match(src, pos)
        if not m:
            if src[pos:].strip() == "":
                break
            raise SyntaxError(src[pos:pos + 40])
        out.append(m.group(1))
        pos = m.end()
    return out


def parse_library(path):
    """Returns (dag, statements) where statements is an ordered list of
    ('let'|'assign', name, node) / ('mstore', off, node) / ('return', off, size)."""
    text = open(path).read()
    start = text.index("assembly {") + len("assembly {")
    depth, i = 1, start
    while depth:
        c = text[i]
        depth += (c == "{") - (c == "}")
        i += 1
    body = text[start:i - 1]
    toks = tokenize(body)
    dag = DAG()
    env = {}
    stmts = []
    p = 0

    def parse_expr():
        nonlocal p
        t = toks[p]
        p += 1
        if t.startswith("0x") or t.isdigit():
            return dag.node("const", val=int(t, 0))
        if toks[p] == "(":
            p += 1
            args = []
            while toks[p] != ")":
                args.append(parse_expr())
                if toks[p] == ",":
                    p += 1
            p += 1
            if t == "calldataload":
                return dag.node("calldataload", val=dag.nodes[args[0]].val)
            return dag.node(t, args)
        if t not in env:
            raise NameError(t)
        return env[t]

    while p < len(toks):
        t = toks[p]
        if t in ("{", "}"):          # nested blocks only scope temporaries; the DAG is sequential
            p += 1
            continue
        if t == "let":
            name = toks[p + 1]
            assert toks[p + 2] == ":="
            p += 3
            env[name] = parse_expr()
            stmts.append(("let", name, env[name]))
        elif toks[p + 1] == ":=":
            name = t
            p += 2
            env[name] = parse_expr()
            stmts.append(("assign", name, env[name]))
        elif t == "mstore":
            p += 2
            off = parse_expr()
            assert toks[p] == ","
            p += 1
            v = parse_expr()
            assert toks[p] == ")"
            p += 1
            stmts.append(("mstore", dag.nodes[off].val, v))
        elif t == "return":
            p += 2
            off = parse_expr()
            p += 1
            size = parse_expr()
            p += 1
            stmts.append(("return", dag.nodes[off].val, dag.nodes[size].val))
        else:
            raise SyntaxError(toks[p:p + 5])
    # the field modulus is the constant used as third operand of mulmod/addmod
    mods = {}
    for n in dag.nodes:
        if n.kind in ("mulmod", "addmod"):
            m = dag.nodes[n.args[2]]
            assert m.kind == "const"
            mods[m.val] = mods.get(m.val, 0) + 1
    dag.modulus = max(mods, key=mods.get) if mods else MODULUS
    return dag, stmts


if __name__ == "__main__":
    import sys, collections
    dag, stmts = parse_library(sys.argv[1])
    c = collections.Counter(n.kind for n in dag.nodes)
    print(c)
    print("statements", len(stmts))
    # constants named F?
    consts = [n for n in dag.nodes if n.kind == "const"]
    print("distinct consts", len(consts), "max users on a const", max(len(n.users) for n in consts))
