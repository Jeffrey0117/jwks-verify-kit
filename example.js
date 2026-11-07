// 可直接跑：node example.js
//
// 起一個假的 IdP（真的 HTTP server + 真的 JWKS 端點 + 真的 ES256 簽章），
// 然後示範驗證器該放行什麼、該擋什麼。沒有 mock，所見即實際行為。

const crypto = require("node:crypto");
const http = require("node:http");
const { createJwksVerifier } = require("./index");

const APP_ID = "app_demo";
const KID = "demo-key-1";

// ── 假的 IdP ────────────────────────────────────────────────────────────────
const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwks = { keys: [{ ...publicKey.export({ format: "jwk" }), kid: KID, use: "sig", alg: "ES256" }] };

const idp = http.createServer((req, res) => {
  if (req.url === "/api/jwks") {
    res.writeHead(200, { "content-type": "application/json", "cache-control": "max-age=3600" });
    return res.end(JSON.stringify(jwks));
  }
  res.writeHead(404).end();
});

function sign(payload, { alg = "ES256", secret, der = false } = {}) {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const input = `${b64({ alg, typ: "JWT", kid: KID })}.${b64(payload)}`;
  const sig = secret
    ? crypto.createHmac("sha256", secret).update(input).digest("base64url")
    : crypto.sign("sha256", Buffer.from(input), {
      key: privateKey, ...(der ? {} : { dsaEncoding: "ieee-p1363" }),
    }).toString("base64url");
  return `${input}.${sig}`;
}

// ── 跑起來 ──────────────────────────────────────────────────────────────────
async function main() {
  await new Promise((r) => idp.listen(0, "127.0.0.1", r));
  const port = idp.address().port;
  console.log(`假 IdP 跑在 http://127.0.0.1:${port}/api/jwks\n`);

  const auth = createJwksVerifier({
    jwksUrl: `http://127.0.0.1:${port}/api/jwks`,
    requiredClaims: { app: APP_ID },        // 租戶邊界
    onError: (e) => console.warn("  [jwks error]", e.message),
  });

  await auth.ready();                        // 開機預熱
  console.log("JWKS 狀態：", auth.stats(), "\n");

  const exp = Math.floor(Date.now() / 1000) + 3600;
  const cases = [
    ["正常 token", sign({ sub: "u1", app: APP_ID, email: "a@x.com", role: "admin", exp })],
    ["HS256（app secret 外洩自簽）", sign({ sub: "attacker", app: APP_ID, role: "admin", exp }, { secret: "leaked" })],
    ["別的 app 的 token", sign({ sub: "u1", app: "app_other", exp })],
    ["沒有 app claim", sign({ sub: "u1", exp })],
    ["沒有 exp（永不過期）", sign({ sub: "u1", app: APP_ID })],
    ["exp 是字串", sign({ sub: "u1", app: APP_ID, exp: String(exp) })],
    ["已過期", sign({ sub: "u1", app: APP_ID, exp: Math.floor(Date.now() / 1000) - 1 })],
    ["DER 編碼的簽章", sign({ sub: "u1", app: APP_ID, exp }, { der: true })],
    ["payload 被改過", (() => {
      const [h, , s] = sign({ sub: "u1", app: APP_ID, exp }).split(".");
      const evil = Buffer.from(JSON.stringify({ sub: "admin", app: APP_ID, exp })).toString("base64url");
      return `${h}.${evil}.${s}`;
    })()],
    ["alg: none", (() => {
      const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
      return `${b64({ alg: "none", typ: "JWT", kid: KID })}.${b64({ sub: "admin", app: APP_ID, exp })}.${"A".repeat(86)}`;
    })()],
  ];

  for (const [label, token] of cases) {
    const claims = auth.verifySync(token);
    const verdict = claims ? `✅ 放行  sub=${claims.sub} role=${claims.role || "-"}` : "⛔ 拒絕";
    console.log(`${verdict}   ${label}`);
  }

  console.log("\nbearer() 取 token（RFC 6750 不分大小寫）：");
  for (const h of ["Bearer abc.def.ghi", "bearer abc.def.ghi", "Basic abc", "Bearer "]) {
    console.log(`  ${JSON.stringify(h).padEnd(24)} -> ${JSON.stringify(auth.bearer(h))}`);
  }

  auth.stop();
  idp.close();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
