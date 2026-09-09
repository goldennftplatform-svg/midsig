-- Pure-function subset of rspamd/lua/midsig.lua, kept verbatim for testing
-- under any Lua 5.x interpreter (fengari + bit shim locally, LuaJIT on rspamd).
-- Do NOT edit independently; mirror changes back into midsig.lua.

local bit = require "bit"
local band, bor, bxor = bit.band, bit.bor, bit.bxor
local bnot, rshift, lshift, rol = bit.bnot, bit.rshift, bit.lshift, bit.rol
local function ror(x, n) return bor(rshift(x, n), lshift(x, (32 - n) % 32)) end

local K = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local function sha256(msg)
  local len = #msg
  local bitlen = len * 8
  local with_one = len + 1
  local padded = with_one + ((64 - ((with_one + 8) % 64)) % 64) + 8
  local buf = {}
  for i = 1, len do
    buf[i] = msg:byte(i)
  end
  buf[len + 1] = 0x80
  for i = len + 2, padded - 8 do
    buf[i] = 0
  end
  for i = 0, 7 do
    buf[padded - i] = math.floor(bitlen / (2 ^ (8 * i))) % 256
  end

  local h0 = 0x6a09e667
  local h1 = 0xbb67ae85
  local h2 = 0x3c6ef372
  local h3 = 0xa54ff53a
  local h4 = 0x510e527f
  local h5 = 0x9b05688c
  local h6 = 0x1f83d9ab
  local h7 = 0x5be0cd19

  local w = {}
  for off = 0, (padded / 64) - 1 do
    for i = 0, 15 do
      local b = off * 64 + i * 4
      w[i + 1] = bor(lshift(buf[b + 1], 24), lshift(buf[b + 2], 16),
                     lshift(buf[b + 3], 8), buf[b + 4])
    end
    for i = 17, 64 do
      local s0 = bxor(bxor(ror(w[i - 15], 7), ror(w[i - 15], 18)), rshift(w[i - 15], 3))
      local s1 = bxor(bxor(ror(w[i - 2], 17), ror(w[i - 2], 19)), rshift(w[i - 2], 10))
      w[i] = band(w[i - 16] + s0 + w[i - 7] + s1, 0xffffffff)
    end

    local a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
    for i = 1, 64 do
      local S1 = bxor(bxor(ror(e, 6), ror(e, 11)), ror(e, 25))
      local ch = bxor(band(e, f), band(bnot(e), g))
      local t1 = band(h + S1 + ch + K[i] + w[i], 0xffffffff)
      local S0 = bxor(bxor(ror(a, 2), ror(a, 13)), ror(a, 22))
      local maj = bxor(bxor(band(a, b), band(a, c)), band(b, c))
      local t2 = band(S0 + maj, 0xffffffff)
      h, g, f, e, d, c, b, a = g, f, e, band(d + t1, 0xffffffff), c, b, a, band(t1 + t2, 0xffffffff)
    end

    h0 = band(h0 + a, 0xffffffff)
    h1 = band(h1 + b, 0xffffffff)
    h2 = band(h2 + c, 0xffffffff)
    h3 = band(h3 + d, 0xffffffff)
    h4 = band(h4 + e, 0xffffffff)
    h5 = band(h5 + f, 0xffffffff)
    h6 = band(h6 + g, 0xffffffff)
    h7 = band(h7 + h, 0xffffffff)
  end

  return string.format("%08x%08x%08x%08x%08x%08x%08x%08x",
    h0, h1, h2, h3, h4, h5, h6, h7)
end

local function leading_zeros_hex(hex)
  local zeros = 0
  for i = 1, #hex do
    local ch = hex:sub(i, i)
    if ch == "0" then
      zeros = zeros + 4
    else
      local nibble = tonumber(ch, 16)
      if nibble >= 8 then break end
      if nibble >= 4 then zeros = zeros + 1; break end
      if nibble >= 2 then zeros = zeros + 2; break end
      zeros = zeros + 3
      break
    end
  end
  return zeros
end

local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local B64_INDEX = {}
for i = 1, #B64 do
  B64_INDEX[B64:sub(i, i)] = i - 1
end

local function b64decode(s)
  local out = {}
  local buf, bits = 0, 0
  for i = 1, #s do
    local c = s:sub(i, i)
    if c ~= "=" then
      local v = B64_INDEX[c]
      if v == nil then return nil end
      buf = buf * 64 + v
      bits = bits + 6
      if bits >= 8 then
        bits = bits - 8
        table.insert(out, string.char(math.floor(buf / (2 ^ bits)) % 256))
      end
    end
  end
  return table.concat(out)
end

local function parse_fields(value)
  local fields = {}
  for part in (value .. ";"):gmatch("([^;]*)") do
    local eq = part:find("=", 1, true)
    if eq then
      local k = part:sub(1, eq - 1):match("^%s*(.-)%s*$"):lower()
      local v = part:sub(eq + 1):match("^%s*(.-)%s*$")
      fields[k] = v
    end
  end
  return fields
end

-- ---------------------------------------------------------------- asserts

local function assert_eq(got, want, label)
  if got ~= want then
    error(string.format("%s: got %q want %q", label, tostring(got), tostring(want)), 2)
  end
  print("ok - " .. label)
end

-- RFC 6234 / FIPS-180 test vectors
assert_eq(sha256("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256(abc)")
assert_eq(sha256(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256(empty)")
assert_eq(sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", "sha256(56 bytes)")

-- base64
assert_eq(b64decode("aGVsbG8="), "hello", "b64decode(hello)")
assert_eq(b64decode("drMbs87P60AvbAsABc3MttyypOFbQwOnNYB2y7N1Cws="):len(), 32, "b64decode(32-byte key)")

-- postage cross-language: this hash was produced by the Python implementation
-- for the fixed challenge below — the two runtimes must agree bit-for-bit.
local challenge = "mailstamp1:aisp.live\n<cross-lang-1@aisp.live>\n1789000000\n0000000000012345"
local hash = sha256(challenge)
assert_eq(hash, "f846eb9df79420c8391676c1610860ccba8c7c4ad48d86cc690b8dbe8d3399e7",
  "postage sha256 matches python")
assert_eq(leading_zeros_hex("000010"), 19, "leading zeros count")

-- parse_fields
local f = parse_fields("v=1; d=aisp.live; i=<x@aisp.live>; t=1789000000; s=AA==")
assert_eq(f.d, "aisp.live", "parse_fields d")
assert_eq(f.i, "<x@aisp.live>", "parse_fields i")
assert_eq(f.s, "AA==", "parse_fields s")

print("ALL PURE-FUNCTION TESTS PASSED")
