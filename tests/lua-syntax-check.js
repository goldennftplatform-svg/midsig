// Syntax-check midsig.lua with luaparse
const fs = require("fs");
const luaparse = require("luaparse");

const file = process.argv[2];
const src = fs.readFileSync(file, "utf8");
try {
  luaparse.parse(src, { luaVersion: "5.1" });
  console.log("syntax OK (Lua 5.1)");
} catch (e) {
  console.error("SYNTAX ERROR:", e.message);
  process.exit(1);
}
