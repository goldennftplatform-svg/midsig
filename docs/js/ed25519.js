// Ed25519 verify (RFC 8032) in pure JS — BigInt arithmetic + WebCrypto SHA-512.
// ESM. Vector-tested against the official RFC 8032 cases (tests/ed25519-vectors.mjs).

const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const D = mod(-121665n * modinv(121666n, P), P);
const SQRT_M1 = powmod(2n, (P - 1n) / 4n, P);
const BY = mod(4n * modinv(5n, P), P);
const BX = xrecover(BY);
const BASE = [BX, BY, 1n, mod((BX * BY), P)];

function mod(a, m) { return ((a % m) + m) % m; }
function powmod(b, e, m) { let r = 1n; b = mod(b, m); while (e > 0n) { if (e & 1n) r = mod(r * b, m); b = mod(b * b, m); e >>= 1n; } return r; }
function modinv(a, m) { return powmod(mod(a, m), m - 2n, m); }

function xrecover(y) {
  const xx = mod((y * y - 1n) * modinv(mod(D * y * y + 1n, P), P), P);
  let x = powmod(xx, (P + 3n) / 8n, P);
  if (mod(x * x - xx, P) !== 0n) x = mod(x * SQRT_M1, P);
  if ((x & 1n) !== 0n) x = P - x;
  return x;
}

function pointAdd(p1, p2) {
  const [x1, y1, z1, t1] = p1, [x2, y2, z2, t2] = p2;
  const a = mod((y1 - x1) * (y2 - x2), P);
  const b = mod((y1 + x1) * (y2 + x2), P);
  const c = mod(t1 * 2n * D * t2, P);
  const dd = mod(z1 * 2n * z2, P);
  const e = mod(b - a, P);
  const f = mod(dd - c, P);
  const g = mod(dd + c, P);
  const h = mod(b + a, P);
  return [mod(e * f, P), mod(g * h, P), mod(f * g, P), mod(e * h, P)];
}

function pointDbl(p1) {
  const [x1, y1, z1, t1] = p1;
  const a = mod(x1 * x1, P);
  const b = mod(y1 * y1, P);
  const c = mod(2n * z1 * z1, P);
  const d = mod(-a, P);
  const e = mod((x1 + y1) * (x1 + y1) - a - b, P);
  const g = mod(d + b, P);
  const f = mod(g - c, P);
  const h = mod(d - b, P);
  return [mod(e * f, P), mod(g * h, P), mod(f * g, P), mod(e * h, P)];
}

function scalarmult(point, scalar) {
  let q = [0n, 1n, 1n, 0n];
  for (let i = 0; i < 256; i++) {
    if ((scalar >> BigInt(i)) & 1n) q = pointAdd(q, point);
    point = pointDbl(point);
  }
  return q;
}

function encodePoint(p) {
  const [x, y, z] = p;
  const zi = modinv(z, P);
  const xx = mod(x * zi, P);
  const yy = mod(y * zi, P);
  const val = yy | ((xx & 1n) << 255n);
  const out = new Uint8Array(32);
  let v = val;
  for (let i = 0; i < 32; i++) { out[i] = Number(v & 255n); v >>= 8n; }
  return out;
}

function decodePoint(u8) {
  const raw = u8ToBig(u8);
  const y = raw & ((1n << 255n) - 1n);
  let x = xrecover(y);
  if ((x & 1n) !== ((raw >> 255n) & 1n)) x = P - x;
  return [mod(x, P), mod(y, P), 1n, mod(x * y, P)];
}

function u8ToBig(u8) {
  let x = 0n;
  for (let i = u8.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(u8[i]);
  return x;
}

function concat(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

async function sha512(u8) {
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-512", u8));
}

export async function verify(pub, message, sig) {
  if (!(pub instanceof Uint8Array) || pub.length !== 32) return false;
  if (sig.length !== 64) return false;
  const renc = sig.slice(0, 32);
  const senc = sig.slice(32, 64);
  const s = u8ToBig(senc);
  if (s >= L) return false;
  let A, R;
  try {
    A = decodePoint(pub);
    R = decodePoint(renc);
  } catch (e) {
    return false;
  }
  const k = mod(u8ToBig(await sha512(concat(renc, pub, message))), L);
  const left = scalarmult(BASE, s);
  const right = pointAdd(R, scalarmult(A, k));
  return bytesEqual(encodePoint(left), encodePoint(right));
}
