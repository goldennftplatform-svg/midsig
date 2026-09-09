// Run tests/rspamd-pure.lua under fengari with a LuaJIT-compatible `bit` shim.
// Usage: cd tests && npm install && node run-lua-tests.js
const path = require("path");
const { lua, lauxlib, lualib, to_luastring, to_jsstring } = require("fengari");

const u32 = (x) => x >>> 0;
const bit = {
  band: (a, b, ...rest) => rest.reduce((r, x) => u32(r & x), u32(a & b)),
  bor: (a, b, ...rest) => rest.reduce((r, x) => u32(r | x), u32(a | b)),
  bxor: (a, b, ...rest) => rest.reduce((r, x) => u32(r ^ x), u32(a ^ b)),
  bnot: (a) => u32(~a),
  rshift: (a, b) => a >>> b,
  lshift: (a, b) => u32(a << b),
  rol: (x, n) => u32((x << n) | (x >>> (32 - n))),
};

const L = lauxlib.luaL_newstate();
lualib.luaL_openlibs(L);

for (const [name, fn] of Object.entries(bit)) {
  lua.lua_pushcfunction(L, (L2) => {
    try {
      const args = [];
      for (let i = 1; i <= lua.lua_gettop(L2); i++) args.push(lua.lua_tointeger(L2, i) >>> 0);
      lua.lua_pushinteger(L2, fn(...args) | 0);
      return 1;
    } catch (e) {
      console.error("SHIM THROW in " + name + ":", e);
      return 0;
    }
  });
  lua.lua_setglobal(L, to_luastring(name));
}

lua.lauxlib = null; // noop
lauxlib.luaL_dostring(
  L,
  to_luastring(`
    local t = {}
    for k, v in pairs({band='band',bor='bor',bxor='bxor',bnot='bnot',rshift='rshift',lshift='lshift',rol='rol'}) do
      t[v] = _G[v]
    end
    package.loaded['bit'] = t
  `)
);

const target = (process.argv[2] || "rspamd-pure.lua").replace(/\\/g, "\\\\");
const wrapped = to_luastring(`
  local ok, err = pcall(function() dofile('${target}') end)
  if not ok then
    print('LUAERR: ' .. tostring(err))
    print('LUAERRTYPE: ' .. type(err))
    print(debug.traceback('', 2))
    os.exit(1)
  end
`);

const status = lauxlib.luaL_dostring(L, wrapped);
if (status !== lua.LUA_OK) {
  console.error("LUA ERROR:", to_jsstring(lua.lua_tostring(L, -1)));
  process.exit(1);
}
