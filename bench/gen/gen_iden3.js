// circomlibjs@0.1.7 - the bytecode the shielded pool's contract repository deploys via tasks/overrides.ts
const { poseidonContract } = require('circomlibjs');
const fs = require('fs');
for (const n of [2, 3]) fs.writeFileSync(`iden3_T${n + 1}.hex`, poseidonContract.createCode(n));
console.log('wrote iden3_T3.hex iden3_T4.hex');
