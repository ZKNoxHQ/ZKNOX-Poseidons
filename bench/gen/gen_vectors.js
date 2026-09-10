const { buildPoseidonOpt } = require('circomlibjs');
const fs = require('fs');
(async () => {
  const p = await buildPoseidonOpt(), F = p.F;
  const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  const rnd = () => { let x = 0n; for (let i = 0; i < 8; i++) x = (x << 32n) | BigInt(Math.floor(Math.random() * 2 ** 32)); return x; };
  const out = { t3: [], t4: [] };
  const edge = [0n, 1n, 2n, P - 1n, P, P + 1n, (1n << 256n) - 1n, (1n << 255n), 3n * P + 7n];
  for (const [key, n] of [["t3", 2], ["t4", 3]]) {
    for (const e of edge) for (let j = 0; j < 3; j++) {
      const v = Array.from({ length: n }, (_, i) => (i === j % n) ? e : rnd());
      out[key].push({ in: v.map(x => x.toString()), out: F.toObject(p(v.map(x => x % P))).toString() });
    }
    for (let i = 0; i < 400; i++) {
      const v = Array.from({ length: n }, rnd);
      out[key].push({ in: v.map(x => x.toString()), out: F.toObject(p(v.map(x => x % P))).toString() });
    }
    out[key].push({ in: Array.from({ length: n }, (_, i) => String(i + 1)), out: F.toObject(p(Array.from({ length: n }, (_, i) => BigInt(i + 1)))).toString() });
  }
  fs.writeFileSync('vectors.json', JSON.stringify(out));
  console.log('vectors', out.t3.length, out.t4.length);
})();
