// Minimal ABI helpers so the ffi scripts have no dependencies beyond @qorechain/pqc.

export const hexToBytes = (h) => {
  const s = h.startsWith('0x') ? h.slice(2) : h;
  if (s.length % 2 !== 0 || /[^0-9a-fA-F]/.test(s)) throw new Error(`bad hex: ${h.slice(0, 20)}…`);
  return Uint8Array.from(Buffer.from(s, 'hex'));
};

export const bytesToHex = (b) => '0x' + Buffer.from(b).toString('hex');

const word = (n) => {
  const out = new Uint8Array(32);
  let v = BigInt(n);
  for (let i = 31; i >= 0 && v > 0n; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
};

const concat = (parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

const padded = (b) => concat([word(b.length), b, new Uint8Array((32 - (b.length % 32)) % 32)]);

/** abi.encode(bytes, bytes, ...) */
export const encodeBytesTuple = (...items) => {
  const head = [];
  const tail = [];
  let offset = 32 * items.length;
  for (const it of items) {
    head.push(word(offset));
    const t = padded(it);
    tail.push(t);
    offset += t.length;
  }
  return concat([...head, ...tail]);
};

/** abi.encode(bool) */
export const encodeBool = (v) => word(v ? 1 : 0);

export { concat };
