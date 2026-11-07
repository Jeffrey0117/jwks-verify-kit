const test = require("node:test");
const assert = require("node:assert/strict");

const { createJwksVerifier, createLetMeUseVerifier } = require("..");
const {
  keypair, toJwk, fakeFetch, signToken, signHs256, nowSec, withCleanEnv,
} = require("./helpers");

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
  minRefreshIntervalMs: 0,
  onError: () => {},
  autoStart: false,
  ...extra,
});

test("ready() → verifySync 通,並回傳 stats", async () => {
  const v = createJwksVerifier(opts({ requiredClaims: { app: APP } }));
  const s = await v.ready();
  assert.equal(s.keys, 1);
  assert.equal(v.verifySync(token()).sub, "u1");
  assert.equal(v.verifySync(token({ app: "other" })), null);
  v.stop();
});

test("autoStart 預設開啟（宿主實際走的那條路）", async () => {
  const impl = fakeFetch(JWKS);
  const v = createJwksVerifier({
    jwksUrl: "https://idp.test/jwks", fetchImpl: impl, refreshMs: 0, onError: () => {},
  });
  await v.whenIdle();
  assert.equal(impl.calls.length, 1, "建構時就該抓一次");
  assert.ok(v.verifySync(token()));
  v.stop();
});

test("ready() 重複呼叫共用同一次抓取", async () => {
  const impl = fakeFetch(JWKS);
  const v = createJwksVerifier(opts({ fetchImpl: impl }));
  await Promise.all([v.ready(), v.ready(), v.ready()]);
  assert.equal(impl.calls.length, 1);
  v.stop();
});

test("🔒 stop() 之後再 ready() 要重新裝回定時刷新", async () => {
  // 原本 ready() 會記住第一次的 promise,stop() 把定時器收掉之後就再也裝不回去
  // → 快取停在最後一次內容,直到 maxStaleMs（預設 24h）才翻成「沒金鑰」全部 401。
  const impl = fakeFetch(JWKS);
  const v = createJwksVerifier(opts({ fetchImpl: impl, refreshMs: 25 }));
  await v.ready();
  v.stop();
  const before = impl.calls.length;
  await v.ready();
  await new Promise((r) => setTimeout(r, 120));
  v.stop();
  assert.ok(impl.calls.length > before + 1, `定時刷新該復活,calls ${before} -> ${impl.calls.length}`);
});

test("ready({ strict: true }) 在 IdP 掛掉時 reject", async () => {
  const v = createJwksVerifier(opts({ fetchImpl: async () => { throw new Error("DNS down"); } }));
  const s = await v.ready();            // 寬鬆版：resolve,但 keys 是 0
  assert.equal(s.keys, 0);
  assert.match(s.lastError, /DNS down/);
  const v2 = createJwksVerifier(opts({ fetchImpl: async () => { throw new Error("DNS down"); } }));
  await assert.rejects(() => v2.ready({ strict: true }), /預熱失敗/);
  v.stop(); v2.stop();
});

test("🔒 沒預熱時 verifySync 拒絕,但 verifyAsync 會等到金鑰", async () => {
  const v1 = createJwksVerifier(opts({ missCooldownMs: 0 }));
  assert.equal(v1.verifySync(token()), null, "冷快取 fail-closed");
  v1.stop();

  const v2 = createJwksVerifier(opts({ missCooldownMs: 0 }));
  assert.ok(await v2.verifyAsync(token()), "async 版第一個請求就該成功");
  v2.stop();
});

test("🔒 沒有叫做 verify 的方法（忘了 await 會讓 truthy Promise 被當成已驗證）", () => {
  const v = createJwksVerifier(opts());
  assert.equal(v.verify, undefined, "短名字不該是那顆地雷");
  assert.equal(typeof v.verifyAsync, "function");
  assert.equal(typeof v.verifySync, "function");
  v.stop();
});

test("🔒 verifySync / verifyAsync 沒有「每次呼叫覆寫選項」的第二參數", async () => {
  // 淺層 spread 的第二參數可以把建構時設好的 requiredClaims / issuer / exp
  // 整個換掉 —— 那正是這個 kit 要消滅的 fail-open,而且形狀很自然
  //（「這條路由還要額外 role: admin」）。
  const v = createJwksVerifier(opts({ requiredClaims: { app: APP } }));
  await v.ready();
  const foreign = token({ app: "app_OTHER" });
  assert.equal(v.verifySync(foreign, { requiredClaims: { role: "x" } }), null);
  assert.equal(v.verifySync(foreign, { requiredClaims: {} }), null);
  assert.equal(await v.verifyAsync(foreign, { requiredClaims: {} }), null);
  const expired = token({ exp: nowSec() - 10 });
  assert.equal(v.verifySync(expired, { now: 1 }), null);
  assert.equal(v.verifySync(expired, { clockToleranceSec: 1e12 }), null);
  v.stop();
});

test("🔒 宿主事後改動它傳進來的 requiredClaims 不該改變驗證結果", async () => {
  const mutable = { app: APP };
  const v = createJwksVerifier(opts({ requiredClaims: mutable }));
  await v.ready();
  assert.ok(v.verifySync(token()));
  mutable.app = "app_OTHER";
  assert.ok(v.verifySync(token()), "選項已凍結拷貝,不受外部改動影響");
  v.stop();
});

test("baseUrl + jwksPath 組網址;預設走 .well-known", () => {
  const a = createJwksVerifier(opts({ jwksUrl: undefined, baseUrl: "https://idp.test/" }));
  assert.equal(a.jwksUrl, "https://idp.test/.well-known/jwks.json");
  a.stop();
  const b = createJwksVerifier(opts({ jwksUrl: undefined, baseUrl: "https://idp.test", jwksPath: "api/jwks" }));
  assert.equal(b.jwksUrl, "https://idp.test/api/jwks");
  b.stop();
});

test("🔒 JWKS 網址必須走 https（它就是信任根）", () => {
  assert.throws(() => createJwksVerifier(opts({ jwksUrl: "http://idp.test/jwks" })), /必須走 https/);
  assert.throws(() => createJwksVerifier(opts({ jwksUrl: "file:///C:/Windows/win.ini" })), /必須走 https/);
  assert.throws(() => createJwksVerifier(opts({ jwksUrl: "not a url" })), /網址無效/);
  // localhost 的明文是合法的（同機直連不經網路,生態系常態）
  const local = createJwksVerifier(opts({ jwksUrl: "http://localhost:4006/api/jwks" }));
  assert.equal(local.jwksUrl, "http://localhost:4006/api/jwks");
  local.stop();
  const ip = createJwksVerifier(opts({ jwksUrl: "http://127.0.0.1:4006/api/jwks" }));
  ip.stop();
  // 真的要對外明文得明確表態
  const forced = createJwksVerifier(opts({ jwksUrl: "http://idp.test/jwks", allowInsecureHttp: true }));
  forced.stop();
});

test("不支援或型別錯誤的 algorithms → 建構時就 throw", () => {
  assert.throws(() => createJwksVerifier(opts({ algorithms: ["RS256"] })), /不支援的 algorithm/);
  assert.throws(() => createJwksVerifier(opts({ algorithms: ["HS256"] })), /不支援的 algorithm/);
  assert.throws(() => createJwksVerifier(opts({ algorithms: "ES384" })), /非空的字串陣列/);
  assert.throws(() => createJwksVerifier(opts({ algorithms: [] })), /非空的字串陣列/);
});

test("🔒 非有限數字的選項 → 建構時就 throw（NaN 會靜默關掉保護）", () => {
  // `timeoutMs: Number(process.env.X)` 在 env 沒設時是 NaN → 逾時整個消失
  // → 卡死的 fetch 讓 promise 永不 settle,正是這個 kit 要消滅的 bug。
  for (const key of ["timeoutMs", "maxStaleMs", "refreshMs", "missCooldownMs", "clockToleranceSec", "maxKeys"]) {
    assert.throws(() => createJwksVerifier(opts({ [key]: NaN })), /有限數字/, `${key}: NaN`);
    assert.throws(() => createJwksVerifier(opts({ [key]: -1 })), /有限數字/, `${key}: -1`);
    assert.throws(() => createJwksVerifier(opts({ [key]: "5000" })), /有限數字/, `${key}: 字串`);
  }
  // 0 仍然是合法的「明確關閉」
  const v = createJwksVerifier(opts({ timeoutMs: 0, maxStaleMs: 0, refreshMs: 0 }));
  v.stop();
});

test("requiredClaims / allowedClaims 型別錯誤 → 建構時就 throw", () => {
  assert.throws(() => createJwksVerifier(opts({ requiredClaims: '{"app":"x"}' })), /必須是物件/);
  assert.throws(() => createJwksVerifier(opts({ requiredClaims: ["app"] })), /必須是物件/);
  assert.throws(() => createJwksVerifier(opts({ allowedClaims: "app" })), /必須是物件/);
});

test("allowedClaims：多租戶（selfize 那種一個服務服務多個 app）", async () => {
  const v = createJwksVerifier(opts({ allowedClaims: { app: [APP, "app_two"] } }));
  await v.ready();
  assert.ok(v.verifySync(token()));
  assert.ok(v.verifySync(token({ app: "app_two" })));
  assert.equal(v.verifySync(token({ app: "app_three" })), null);
  v.stop();
  // 空清單 → 拒絕全部（fail-closed）
  const empty = createJwksVerifier(opts({ allowedClaims: { app: [] } }));
  await empty.ready();
  assert.equal(empty.verifySync(token()), null);
  empty.stop();
});

test("stats() 曝露 fail-closed 的原因（別讓它變無聲故障）", async () => {
  const v = createJwksVerifier(opts({ jwksUrl: undefined, baseUrl: undefined }));
  const s = await v.ready();
  assert.equal(s.keys, 0);
  assert.ok(s.lastError);
  v.stop();
});

test("bearer() 掛在 verifier 上,方便一行取 token", () => {
  const v = createJwksVerifier(opts());
  assert.equal(v.bearer("bearer abc"), "abc");
  v.stop();
});

test("ES384 / ES512 走完整的 JWKS 路徑（ES512 的曲線是 P-521 不是 P-512）", async () => {
  for (const [alg, curve] of [["ES384", "secp384r1"], ["ES512", "secp521r1"]]) {
    const kp = keypair(curve);
    const v = createJwksVerifier(opts({
      algorithms: [alg],
      fetchImpl: fakeFetch({ keys: [toJwk(kp.publicKey, "kid-1")] }),
      requiredClaims: { app: APP },
    }));
    await v.ready();
    assert.equal(v.stats().keys, 1, `${alg}: 金鑰該載進來`);
    const t = signToken({ sub: "u1", app: APP, exp: future() },
      { key: kp.privateKey, alg, header: { kid: "kid-1" } });
    assert.ok(v.verifySync(t), `${alg}: 真 token 該通`);
    v.stop();
  }
});

// ── LetMeUse 預設 ───────────────────────────────────────────────────────────

test("🔒 createLetMeUseVerifier 缺 appId 直接 throw（租戶邊界不能靠運氣）", async () => {
  await withCleanEnv(() => {
    assert.throws(() => createLetMeUseVerifier({ jwksUrl: "https://x/jwks" }), /appId/);
    assert.throws(() => createLetMeUseVerifier({ jwksUrl: "https://x/jwks", appId: "" }), /appId/);
    assert.throws(() => createLetMeUseVerifier({ jwksUrl: "https://x/jwks", appId: "   " }), /appId/);
  });
});

test("🔒 createLetMeUseVerifier 缺網址也直接 throw（areyoubot 的那種故障）", async () => {
  await withCleanEnv(() => {
    assert.throws(() => createLetMeUseVerifier({ appId: APP }), /jwksUrl 或 baseUrl/);
  });
});

test("env 的值會 trim（.env 的 CRLF 尾巴會讓每顆真 token 被拒絕）", async () => {
  await withCleanEnv(async () => {
    process.env.LETMEUSE_APP_ID = `${APP}\r`;
    process.env.LETMEUSE_BASE_URL = " https://letmeuse.test \r";
    const v = createLetMeUseVerifier({
      fetchImpl: fakeFetch(JWKS), refreshMs: 0, autoStart: false, onError: () => {},
    });
    assert.equal(v.jwksUrl, "https://letmeuse.test/api/jwks");
    await v.ready();
    assert.ok(v.verifySync(token()), "trim 過的 appId 該比得中");
    v.stop();
  });
});

test("🔒 明確傳入的網址優先於 env（env 蓋掉參數無法 debug）", async () => {
  await withCleanEnv(async () => {
    process.env.LETMEUSE_JWKS_URL = "https://stale-env.example/api/jwks";
    const v = createLetMeUseVerifier({
      appId: APP, baseUrl: "https://explicit.test", autoStart: false, refreshMs: 0, onError: () => {},
    });
    assert.equal(v.jwksUrl, "https://explicit.test/api/jwks");
    v.stop();
  });
});

test("createLetMeUseVerifier：app claim 自動成為必要條件,HS256 仍然擋掉", async () => {
  const v = createLetMeUseVerifier({
    appId: APP,
    jwksUrl: "https://letmeuse.test/api/jwks",
    fetchImpl: fakeFetch(JWKS),
    refreshMs: 0,
    autoStart: false,
    onError: () => {},
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

test("🔒 宿主不能用 requiredClaims 覆寫 app（kit 剛說它是唯一的租戶邊界）", async () => {
  const v = createLetMeUseVerifier({
    appId: APP,
    jwksUrl: "https://letmeuse.test/api/jwks",
    fetchImpl: fakeFetch(JWKS),
    requiredClaims: { app: "app_OTHER" },
    refreshMs: 0,
    autoStart: false,
    onError: () => {},
  });
  await v.ready();
  assert.equal(v.verifySync(token({ app: "app_OTHER" })), null, "appId 必須贏");
  assert.ok(v.verifySync(token()));
  v.stop();
});

test("呼叫端可以額外加 requiredClaims（只能更嚴,不能更鬆）", async () => {
  const v = createLetMeUseVerifier({
    appId: APP,
    jwksUrl: "https://letmeuse.test/api/jwks",
    fetchImpl: fakeFetch(JWKS),
    requiredClaims: { role: "admin" },
    refreshMs: 0,
    autoStart: false,
    onError: () => {},
  });
  await v.ready();
  assert.ok(v.verifySync(token({ role: "admin" })));
  assert.equal(v.verifySync(token({ role: "user" })), null);
  assert.equal(v.verifySync(token({ role: "admin", app: "app_other" })), null);
  v.stop();
});

test("createLetMeUseVerifier 預設 jwksPath 是 /api/jwks（不走 .well-known）", async () => {
  await withCleanEnv(() => {
    const v = createLetMeUseVerifier({
      appId: APP, baseUrl: "https://letmeuse.test", autoStart: false, refreshMs: 0, onError: () => {},
    });
    assert.equal(v.jwksUrl, "https://letmeuse.test/api/jwks");
    v.stop();
  });
});
