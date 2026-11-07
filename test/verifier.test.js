const test = require("node:test");
const assert = require("node:assert/strict");

const { createJwksVerifier, createLetMeUseVerifier } = require("..");
const { keypair, toJwk, fakeFetch, signToken, signHs256, nowSec } = require("./helpers");

const APP = "app_test";
const { publicKey, privateKey } = keypair();
const JWKS = { keys: [toJwk(publicKey, "kid-1")] };
const future = () => nowSec() + 3600;
const token = (extra = {}) => signToken(
  { sub: "u1", app: APP, exp: future(), ...extra },
  { key: privateKey, header: { kid: "kid-1" } },
);

const opts = (extra = {}) => ({
  jwksUrl: "https://idp.test/jwks",
  fetchImpl: fakeFetch(JWKS),
  refreshMs: 0,
  autoStart: false,
  ...extra,
});

test("ready() → verifySync 通", async () => {
  const v = createJwksVerifier(opts({ requiredClaims: { app: APP } }));
  await v.ready();
  assert.equal(v.verifySync(token()).sub, "u1");
  assert.equal(v.verifySync(token({ app: "other" })), null);
  v.stop();
});

test("ready() 重複呼叫共用同一次抓取", async () => {
  const impl = fakeFetch(JWKS);
  const v = createJwksVerifier(opts({ fetchImpl: impl }));
  await Promise.all([v.ready(), v.ready(), v.ready()]);
  assert.equal(impl.calls.length, 1);
  v.stop();
});

test("🔒 沒預熱時 verifySync 拒絕,但 verify()（async）會等到金鑰", async () => {
  const v1 = createJwksVerifier(opts({ missCooldownMs: 0 }));
  assert.equal(v1.verifySync(token()), null, "冷快取 fail-closed");
  v1.stop();

  const v2 = createJwksVerifier(opts({ missCooldownMs: 0 }));
  assert.ok(await v2.verify(token()), "async 版第一個請求就該成功");
  v2.stop();
});

test("baseUrl + jwksPath 組網址;預設走 .well-known", () => {
  const a = createJwksVerifier(opts({ jwksUrl: undefined, baseUrl: "https://idp.test/" }));
  assert.equal(a.jwksUrl, "https://idp.test/.well-known/jwks.json");
  a.stop();
  const b = createJwksVerifier(opts({ jwksUrl: undefined, baseUrl: "https://idp.test", jwksPath: "api/jwks" }));
  assert.equal(b.jwksUrl, "https://idp.test/api/jwks");
  b.stop();
});

test("不支援的 algorithm → 建構時就 throw（不要悄悄忽略）", () => {
  assert.throws(() => createJwksVerifier(opts({ algorithms: ["RS256"] })), /不支援的 algorithm/);
  assert.throws(() => createJwksVerifier(opts({ algorithms: ["HS256"] })), /不支援的 algorithm/);
});

test("stats() 曝露 fail-closed 的原因（別讓它變無聲故障）", async () => {
  const v = createJwksVerifier(opts({ jwksUrl: "", baseUrl: "" }));
  await v.ready();
  const s = v.stats();
  assert.equal(s.keys, 0);
  assert.ok(s.lastError);
  v.stop();
});

test("bearer() 掛在 verifier 上,方便一行取 token", () => {
  const v = createJwksVerifier(opts());
  assert.equal(v.bearer("bearer abc"), "abc");
  v.stop();
});

test("🔒 createLetMeUseVerifier 缺 appId 直接 throw（租戶邊界不能靠運氣）", () => {
  const saved = process.env.LETMEUSE_APP_ID;
  delete process.env.LETMEUSE_APP_ID;
  try {
    assert.throws(() => createLetMeUseVerifier({ jwksUrl: "https://x/jwks" }), /appId/);
    assert.throws(() => createLetMeUseVerifier({ jwksUrl: "https://x/jwks", appId: "" }), /appId/);
  } finally {
    if (saved !== undefined) process.env.LETMEUSE_APP_ID = saved;
  }
});

test("createLetMeUseVerifier：app claim 自動成為必要條件,HS256 仍然擋掉", async () => {
  const v = createLetMeUseVerifier({
    appId: APP,
    jwksUrl: "https://letmeuse.test/api/jwks",
    fetchImpl: fakeFetch(JWKS),
    refreshMs: 0,
    autoStart: false,
  });
  await v.ready();
  assert.equal(v.verifySync(token()).sub, "u1");
  assert.equal(v.verifySync(token({ app: "app_other" })), null);
  assert.equal(
    v.verifySync(signHs256({ sub: "attacker", app: APP, exp: future() }, "leaked-secret")),
    null,
  );
  v.stop();
});

test("createLetMeUseVerifier 預設 jwksPath 是 /api/jwks（LetMeUse 不走 .well-known）", () => {
  const v = createLetMeUseVerifier({
    appId: APP, baseUrl: "https://letmeuse.test", autoStart: false, refreshMs: 0,
  });
  assert.equal(v.jwksUrl, "https://letmeuse.test/api/jwks");
  v.stop();
});

test("呼叫端可以額外加 requiredClaims,不會蓋掉 app", async () => {
  const v = createLetMeUseVerifier({
    appId: APP,
    jwksUrl: "https://letmeuse.test/api/jwks",
    fetchImpl: fakeFetch(JWKS),
    requiredClaims: { role: "admin" },
    refreshMs: 0,
    autoStart: false,
  });
  await v.ready();
  assert.ok(v.verifySync(token({ role: "admin" })));
  assert.equal(v.verifySync(token({ role: "user" })), null);
  assert.equal(v.verifySync(token({ role: "admin", app: "app_other" })), null);
  v.stop();
});
