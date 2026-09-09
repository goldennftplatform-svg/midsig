// RFC 8032 test vectors for docs/js/ed25519.js — run: node tests/ed25519-vectors.mjs
import { verify } from "../docs/js/ed25519.js";

const hex = (s) => Uint8Array.from(Buffer.from(s, "hex"));
const utf8 = (s) => new TextEncoder().encode(s);

const vectors = [
  {
    pub: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    msg: "",
    sig: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
         "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  },
  {
    pub: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    msg: "72",
    sig: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
         "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
  },
  {
    pub: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    msg: "af82",
    sig: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac" +
         "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
  },
];

let failures = 0;
for (const [i, v] of vectors.entries()) {
  const ok = await verify(hex(v.pub), hex(v.msg), hex(v.sig));
  const tampered = await verify(hex(v.pub), hex(v.msg + (v.msg ? "00" : "00")), hex(v.sig));
  console.log(`vector ${i + 1}: verify=${ok} tampered-fails=${!tampered}`);
  if (!ok || tampered) failures++;
}

// Full-flow check: real message signed by the Python implementation,
// verified with live DNS-over-HTTPS (the exact path verify.html uses).
try {
  const eml = new TextDecoder().decode(new Uint8Array(await (await import("node:fs/promises")).readFile(process.argv[2])));
  const headers = eml.split(/\r?\n\r?\n/)[0].replace(/\r\n/g, "\n");
  const lines = [];
  for (const raw of headers.split("\n")) {
    if (/^[ \t]/.test(raw) && lines.length) lines[lines.length - 1] += " " + raw.trim();
    else lines.push(raw);
  }
  const map = {};
  for (const line of lines) {
    const i = line.indexOf(":");
    if (i < 0) continue;
    const name = line.slice(0, i).trim().toLowerCase();
    const value = line.slice(i + 1).trim();
    map[name] = map[name] || [];
    map[name].push(value);
  }
  const from = map["from"][0];
  const angle = from.match(/<([^>]+)>/);
  const addr = angle ? angle[1] : from.trim();
  const domain = addr.split("@")[1].toLowerCase();
  const fields = {};
  for (const part of map["x-midsig"][0].split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k) fields[k.trim().toLowerCase()] = rest.join("=").trim();
  }
  const payload = `midsig1:${domain}\n${fields.i}\n${fields.t}`;
  const sig = Uint8Array.from(Buffer.from(fields.s, "base64"));

  const url = `https://dns.google/resolve?name=_midsig.${domain}&type=TXT`;
  const resp = await (await fetch(url)).json();
  const data = (resp.Answer || []).map((a) => a.data).join(" ");
  const pubB64 = data.match(/p=([A-Za-z0-9+/=]+)/)[1];
  const pub = Uint8Array.from(Buffer.from(pubB64, "base64"));

  const ok = await verify(pub, utf8(payload), sig);
  console.log(`live DoH flow (${domain}): verify=${ok}`);
  if (!ok) failures++;
} catch (e) {
  console.log("live DoH flow: skipped/failed —", e.message);
}

process.exit(failures ? 1 : 0);
