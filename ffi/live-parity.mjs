#!/usr/bin/env node
// Diff the live QoreChain pqcVerify precompile (0x…0a01) against local FIPS-204 ML-DSA-87.
// Read-only: uses eth_call only. Usage: node ffi/live-parity.mjs [rpcUrl]
import { mldsa87 } from '@qorechain/pqc';
import { bytesToHex, encodeBytesTuple, concat, hexToBytes } from './abi.mjs';

const RPC = process.argv[2] ?? 'https://evm-testnet.qore.host';
const PQC_VERIFY = '0x0000000000000000000000000000000000000a01';
const SELECTOR = hexToBytes('0xf52bde0a'); // pqcVerify(bytes,bytes,bytes)

const enc = new TextEncoder();
const { publicKey: pk, secretKey: sk } = mldsa87.keygen(new Uint8Array(32).fill(7));
const msg = enc.encode('pqc-forge parity check');
const sig = mldsa87.sign(sk, msg);
const hedged = mldsa87.sign(sk, msg, { hedged: true });
const flip = (b, i = 0) => { const c = b.slice(); c[i] ^= 1; return c; };

const call = (pk_, sig_, msg_, selector = SELECTOR) => concat([selector, encodeBytesTuple(pk_, sig_, msg_)]);

const cases = [
  ['valid deterministic sig', call(pk, sig, msg), true],
  ['valid hedged sig', call(pk, hedged, msg), true],
  ['tampered message', call(pk, sig, flip(msg)), false],
  ['tampered signature', call(pk, flip(sig, 100), msg), false],
  ['wrong public key', call(flip(pk, 50), sig, msg), false],
  ['short signature (4626 B)', call(pk, sig.slice(0, -1), msg), false],
  // Chain quirk (measured 2026-11-20): FIPS-204 accepts a valid signature over an empty message,
  // the precompile returns false. The mock mirrors the chain.
  ['empty message (chain quirk)', call(pk, mldsa87.sign(sk, new Uint8Array()), new Uint8Array()), false],
  ['wrong selector 0xdeadbeef', call(pk, sig, msg, hexToBytes('0xdeadbeef')), 'revert?'],
  ['garbage calldata', concat([SELECTOR, hexToBytes('0x0102')]), 'revert?'],
];

async function rpc(method, params) {
  const r = await fetch(RPC, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  return r.json();
}

const decodeBool = (hex) => (hex === '0x' ? 'empty-returndata' : BigInt(hex) === 1n);

console.log(`RPC ${RPC}`);
console.log(`chainId ${(await rpc('eth_chainId', [])).result}`);
let mismatches = 0;
for (const [name, data, expected] of cases) {
  const tx = { to: PQC_VERIFY, data: bytesToHex(data) };
  const res = await rpc('eth_call', [tx, 'latest']);
  const live = res.error ? `revert: ${res.error.message}` : decodeBool(res.result);
  let gas = '';
  if (!res.error) {
    const g = await rpc('eth_estimateGas', [tx]);
    gas = g.result ? `  gas=${BigInt(g.result)}` : '';
  }
  const ok = expected === 'revert?' ? String(live).startsWith('revert') : live === expected;
  if (!ok) mismatches++;
  console.log(`${ok ? 'OK  ' : 'DIFF'} ${name.padEnd(28)} live=${live}${gas}  expected=${expected}`);
}
console.log(mismatches ? `\n${mismatches} mismatch(es)` : '\nall cases match');
process.exit(mismatches ? 1 : 0);
