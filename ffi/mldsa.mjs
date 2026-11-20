#!/usr/bin/env node
// pqc-forge ffi bridge: real FIPS-204 ML-DSA-87 for Foundry tests, via @qorechain/pqc.
//
//   keygen <seed32hex>            -> abi.encode(bytes publicKey, bytes secretKey)
//   sign   <skHex> <msgHex|@file> -> abi.encode(bytes signature)   (deterministic)
//   verify <pkHex> <sigHex> <msgHex|@file> -> abi.encode(bool)
//
// Output is a 0x-prefixed hex string, which vm.ffi decodes to raw bytes.
// Arguments may be "@path" to read hex from a file (Windows caps command lines at 32,767 chars).
import { readFileSync } from 'node:fs';
import { mldsa87 } from '@qorechain/pqc';
import { hexToBytes, bytesToHex, encodeBytesTuple, encodeBool } from './abi.mjs';

const arg = (a) => hexToBytes(a.startsWith('@') ? readFileSync(a.slice(1), 'utf8').trim() : a);

const [cmd, ...rest] = process.argv.slice(2);
let out;
switch (cmd) {
  case 'keygen': {
    const seed = arg(rest[0]);
    if (seed.length !== 32) throw new Error('seed must be 32 bytes');
    const { publicKey, secretKey } = mldsa87.keygen(seed);
    out = encodeBytesTuple(publicKey, secretKey);
    break;
  }
  case 'sign': {
    out = encodeBytesTuple(mldsa87.sign(arg(rest[0]), arg(rest[1])));
    break;
  }
  case 'verify': {
    // verify() never throws: malformed sizes return false, matching the chain.
    out = encodeBool(mldsa87.verify(arg(rest[0]), arg(rest[2]), arg(rest[1])));
    break;
  }
  default:
    process.stderr.write('usage: mldsa.mjs keygen|sign|verify ...\n');
    process.exit(2);
}
process.stdout.write(bytesToHex(out));
