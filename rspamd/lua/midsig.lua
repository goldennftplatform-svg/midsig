-- MIDSIG verification module for rspamd
--
-- Verifies the X-Midsig header (domain-signed Message-ID) against the
-- domain's _midsig TXT record, and optionally the X-Midsig-Postage stamp.
--
-- Install: copy to /etc/rspamd/lua/local/midsig.lua (see GUIDE-RSPAMD.md)
-- Crypto: Ed25519 via LuaJIT FFI into libcrypto (OpenSSL 1.1.1+), which is
-- already a hard dependency of rspamd. SHA-256 for postage is pure LuaJIT.
--
-- Symbols emitted:
--   MIDSIG_PASS  — signature valid (score 0, informational)
--   MIDSIG_FAIL  — spoofed/unsigned/missing key (give it weight + force_action)
--   MIDSIG_TEMP  — DNS or crypto failure (score 0; never hard-reject on this)

local rspamd_logger = require "rspamd_logger"
local ffi = require "ffi"
local bit = require "bit"

local config = rspamd_config

-- ---------------------------------------------------------------- settings

local function get_opt(key, default)
  local ok, val = pcall(function()
    return config:get_module_opt("midsig", key)
  end)
  if ok and val ~= nil then
    return val
  end
  return default
end

local required_bits = get_opt("required_bits", 0) or 0
local exempt = get_opt("exempt_domains", {}) or {}
local exempt_domains = {}
for _, d in ipairs(exempt) do
  exempt_domains[string.lower(d)] = true
end

-- ---------------------------------------------------------------- OpenSSL

ffi.cdef[[
typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
const EVP_MD *EVP_sha512(void);
EVP_PKEY *EVP_PKEY_new_raw_public_key(int type, void *e,
                                      const unsigned char *key, size_t keylen);
void EVP_PKEY_free(EVP_PKEY *key);
EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                         const EVP_MD *type, void *e, EVP_PKEY *pkey);
int EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen,
                     const unsigned char *tbs, size_t tbslen);
]]

local NID_ED25519 = 1087

local libcrypto = nil
local sonames = {
  "libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so",
  "libcrypto.dylib", "libcrypto-3-x64.dll", "libcrypto-1_1-x64.dll", "crypto",
}
for _, name in ipairs(sonames) do
  local ok, lib = pcall(ffi.load, name)
  if ok then
    libcrypto = lib
    break
  end
end

-- ---------------------------------------------------------------- helpers

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

local function ed25519_verify(pub_raw, payload, sig_raw)
  if not libcrypto then
    return nil, "openssl unavailable"
  end
  local pkey = libcrypto.EVP_PKEY_new_raw_public_key(NID_ED25519, nil, pub_raw, 32)
  if pkey == nil then
    return nil, "bad public key"
  end
  local ctx = libcrypto.EVP_MD_CTX_new()
  if ctx == nil then
    libcrypto.EVP_PKEY_free(pkey)
    return nil, "no md ctx"
  end
  local init = libcrypto.EVP_DigestVerifyInit(ctx, nil, libcrypto.EVP_sha512(), nil, pkey)
  if init ~= 1 then
    libcrypto.EVP_MD_CTX_free(ctx)
    libcrypto.EVP_PKEY_free(pkey)
    return nil, "digest init failed"
  end
  local r = libcrypto.EVP_DigestVerify(ctx, sig_raw, 64, payload, #payload)
  libcrypto.EVP_MD_CTX_free(ctx)
  libcrypto.EVP_PKEY_free(pkey)
  return r == 1, "bad signature"
end

-- Pure-LuaJIT SHA-256 (used only for postage when required_bits > 0)
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

-- ---------------------------------------------------------------- callbacks

local function emit(task, symbol, reason)
  task:insert_result(symbol, 0.0, reason or "")
end

local function midsig_callback(task)
  local function pass()
    emit(task, "MIDSIG_PASS", "signature valid")
  end
  local function fail(reason)
    emit(task, "MIDSIG_FAIL", reason)
  end
  local function temp(reason)
    emit(task, "MIDSIG_TEMP", reason)
  end

  local from = task:get_header("From")
  if not from or from == "" then
    return fail("no From header")
  end

  local angle = from:match("<([^>]+)>")
  local addr = angle or from:match("^%s*([^%s,]+)%s*$")
  if not addr then
    return fail("unparseable From address")
  end
  local at = addr:find("@", 1, true)
  if not at then
    return fail("From address has no domain")
  end
  local domain = string.lower(addr:sub(at + 1))

  if exempt_domains[domain] then
    return emit(task, "MIDSIG_PASS", "exempt domain " .. domain)
  end

  local midsig = task:get_header("X-Midsig")
  if not midsig or midsig == "" then
    return fail("missing X-Midsig header")
  end

  local fields = parse_fields(midsig)
  local f_domain = fields.d and fields.d:lower()
  if f_domain ~= domain then
    return fail(string.format("d=%s does not match From domain %s",
      tostring(fields.d), domain))
  end
  if not fields.i or not fields.t or not fields.s then
    return fail("malformed X-Midsig header")
  end

  local msgid_header = task:get_header("Message-Id")
  if msgid_header ~= fields.i then
    return fail("X-Midsig i= does not match Message-ID header")
  end

  local sig = b64decode(fields.s)
  if not sig or #sig ~= 64 then
    return fail("signature is not valid base64")
  end

  local payload = "midsig1:" .. domain .. "\n" .. fields.i .. "\n" .. fields.t

  local resolver = task:get_resolver()
  if not resolver then
    return temp("no resolver available")
  end

  local function on_txt(results, err)
    if err then
      return temp("DNS error: " .. tostring(err))
    end
    if not results or #results == 0 then
      return fail("no _midsig TXT record for " .. domain)
    end

    local pub_b64 = nil
    for _, record in ipairs(results) do
      local p = record:match("p=([A-Za-z0-9+/=]+)")
      if p then
        pub_b64 = p
        break
      end
    end
    if not pub_b64 then
      return fail("no ed25519 key in TXT record")
    end
    local pub = b64decode(pub_b64)
    if not pub or #pub ~= 32 then
      return fail("bad public key in TXT record")
    end

    local ok, why = ed25519_verify(pub, payload, sig)
    if not ok then
      if why == "openssl unavailable" then
        return temp("openssl unavailable")
      end
      return fail(why)
    end

    if required_bits > 0 or task:get_header("X-Midsig-Postage") then
      local postage = task:get_header("X-Midsig-Postage")
      if not postage or postage == "" then
        return fail("postage required but missing")
      end
      local p = parse_fields(postage)
      if not p.n or not p.x then
        return fail("malformed postage header")
      end
      local challenge = "mailstamp1:" .. domain .. "\n" .. fields.i .. "\n" ..
        fields.t .. "\n" .. p.n
      local hash = sha256(challenge)
      if hash ~= p.x:lower() then
        return fail("postage token invalid")
      end
      local zeros = leading_zeros_hex(hash)
      if zeros < required_bits then
        return fail(string.format("postage %d bits < required %d", zeros, required_bits))
      end
    end

    return pass()
  end

  local ok, err = pcall(function()
    resolver:resolve_txt("_midsig." .. domain, on_txt, task:get_mempool())
  end)
  if not ok then
    temp("resolve_txt failed: " .. tostring(err))
  end
end

-- ---------------------------------------------------------------- symbols

config:register_symbol({
  name = "MIDSIG_PASS",
  description = "MIDSIG domain signature valid",
  group = "midsig",
})

config:register_symbol({
  name = "MIDSIG_FAIL",
  description = "MIDSIG verification failed (spoofed or unsigned)",
  group = "midsig",
})

config:register_symbol({
  name = "MIDSIG_TEMP",
  description = "MIDSIG verification deferred (DNS/crypto failure)",
  group = "midsig",
})

config:register_symbol({
  name = "MIDSIG_CHECK",
  type = "callback",
  callback = midsig_callback,
  flags = "fine",
  group = "midsig",
})
