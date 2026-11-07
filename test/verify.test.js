const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const { verifyJwt, verifyJwtAsync, bearerToken } = require("../src/verify");
const { keypair, signToken, signRawPayload, signHs256, nowSec } = require("./helpers");

const APP = "app_test";
const { publicKey, privateKey } = keypair();
const getKey = (kid) => (kid === "test-kid" ? publicKey : null);
const base = { getKey, requiredClaims: { app: APP } };

const future = () => nowSec() + 3600;
const past = () => nowSec() - 3600;
const valid = (extra = {}) => signToken({ sub: "u1", app: APP, exp: future(), ...extra }, { key: privateKey });

test("正常 token 回 claims", () => {
  const claims = verifyJwt(valid({ email: "a@x.com", role: "admin" }), base);
  assert.equal(claims.sub, "u1");
  assert.equal(claims.role, "admin");
});

test("🔒 HS256 一律拒絕,就算是用真的 app secret 簽的（pokkit 2026-10-25 回歸）", () => {
  // 攻擊情境：app secret 外洩,攻擊者自簽一顆 admin token。
  // 只收非對稱簽章 → 洩漏的 secret 對偽造毫無用處。
  const forged = signHs256({ sub: "attacker", app: APP, role: "admin", exp: future() }, "leaked-secret");
  assert.equal(verifyJwt(forged, base), null);
  // 連「把 alg 寫成 ES256 但其實是 HMAC」也擋（長度對不上 + 驗簽失敗）
  const confused = signHs256({ sub: "attacker", app: APP, exp: future() }, "leaked-secret", { alg: "ES256" });
  assert.equal(verifyJwt(confused, base), null);
});

test("🔒 alg:none 拒絕", () => {
  const h = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT", kid: "test-kid" })).toString("base64url");
  const p = Buffer.from(JSON.stringify({ sub: "u1", app: APP, exp: future() })).toString("base64url");
  assert.equal(verifyJwt(`${h}.${p}.${"A".repeat(86)}`, base), null);
  assert.equal(verifyJwt(`${h}.${p}.`, base), null);
});

test("🔒 沒有 exp、或 exp 是字串 → 拒絕（無 exp 不得等於永不過期）", () => {
  assert.equal(verifyJwt(signToken({ sub: "u1", app: APP }, { key: privateKey }), base), null);
  assert.equal(verifyJwt(valid({ exp: String(future()) }), base), null);
  assert.equal(verifyJwt(valid({ exp: Infinity }), base), null);
});

test("過期 token 拒絕；nbf 還沒到也拒絕", () => {
  assert.equal(verifyJwt(valid({ exp: past() }), base), null);
  assert.equal(verifyJwt(valid({ nbf: future() }), base), null);
  assert.notEqual(verifyJwt(valid({ nbf: past() }), base), null);
  // 非數字的 nbf 視為可疑,不是忽略
  assert.equal(verifyJwt(valid({ nbf: "later" }), base), null);
});

test("clockToleranceSec 容許小幅時鐘誤差", () => {
  const justExpired = valid({ exp: nowSec() - 3 });
  assert.equal(verifyJwt(justExpired, base), null);
  assert.notEqual(verifyJwt(justExpired, { ...base, clockToleranceSec: 10 }), null);
});

test("🔒 requiredClaims：別的 app、或完全沒帶 app claim,都拒絕", () => {
  // IdP 用同一把金鑰簽所有 app 的 token,所以 app claim 是唯一的租戶邊界
  assert.equal(verifyJwt(valid({ app: "app_other" }), base), null);
  assert.equal(verifyJwt(signToken({ sub: "u1", exp: future() }, { key: privateKey }), base), null);
});

test("🔒 requiredClaims 的期望值是空的 → 拒絕全部（設定不全要壞得大聲）", () => {
  const token = valid();
  for (const bad of [undefined, null, ""]) {
    assert.equal(verifyJwt(token, { getKey, requiredClaims: { app: bad } }), null, `app=${String(bad)}`);
  }
});

test("issuer：設了就比對,設成空值則拒絕全部", () => {
  const token = signToken({ sub: "u1", app: APP, iss: "https://idp.example", exp: future() }, { key: privateKey });
  assert.notEqual(verifyJwt(token, { ...base, issuer: "https://idp.example" }), null);
  assert.equal(verifyJwt(token, { ...base, issuer: "https://evil.example" }), null);
  assert.equal(verifyJwt(token, { ...base, issuer: "" }), null);
  // 沒設 issuer 就不檢查（泛用情境）
  assert.notEqual(verifyJwt(token, base), null);
});

test("🔒 未知 kid 拒絕；header 沒有 kid 也拒絕（擋「猜第一把金鑰」）", () => {
  assert.equal(verifyJwt(valid(), { ...base, getKey: () => null }), null);
  const noKid = signToken({ sub: "u1", app: APP, exp: future() }, { key: privateKey, header: { kid: undefined } });
  assert.equal(verifyJwt(noKid, base), null);
});

test("換一把金鑰簽的 token 拒絕；payload 被改過也拒絕", () => {
  const attacker = keypair();
  const other = signToken({ sub: "u1", app: APP, exp: future() }, { key: attacker.privateKey });
  assert.equal(verifyJwt(other, base), null);

  const [h, , s] = valid().split(".");
  const tampered = Buffer.from(JSON.stringify({ sub: "admin", app: APP, exp: future() })).toString("base64url");
  assert.equal(verifyJwt(`${h}.${tampered}.${s}`, base), null);
});

test("🔒 DER 編碼的簽章拒絕（JWS 規定 raw r||s）", () => {
  const der = signToken({ sub: "u1", app: APP, exp: future() }, { key: privateKey, der: true });
  assert.equal(verifyJwt(der, base), null);
});

test("🔒 嚴格 base64url：字母表外的字元、padding 一律拒絕", () => {
  const [h, p, s] = valid().split(".");
  assert.equal(verifyJwt(`${h}.${p}.${s.slice(0, 40)}!${s.slice(41)}`, base), null);
  assert.equal(verifyJwt(`${h}.${p}.${s}=`, base), null);
  assert.equal(verifyJwt(`${h}.${p}.${s.slice(0, 85)}\n`, base), null);
  assert.equal(verifyJwt(`${h}.${p.replace(/.$/, "+")}.${s}`, base), null);
});

test("格式壞掉的輸入一律回 null,永不 throw", () => {
  for (const bad of ["", "abc", "a.b", "a.b.c.d", null, undefined, 42, {}]) {
    assert.equal(verifyJwt(bad, base), null, JSON.stringify(bad));
  }
  // payload 不是 JSON（但簽章正確）
  const header = Buffer.from(JSON.stringify({ alg: "ES256", typ: "JWT", kid: "test-kid" })).toString("base64url");
  const payload = Buffer.from("not json").toString("base64url");
  const sig = crypto.sign("sha256", Buffer.from(`${header}.${payload}`), {
    key: privateKey, dsaEncoding: "ieee-p1363",
  });
  assert.equal(verifyJwt(`${header}.${payload}.${sig.toString("base64url")}`, base), null);
  // payload 是陣列而非物件
  const arr = Buffer.from(JSON.stringify([1, 2])).toString("base64url");
  const sig2 = crypto.sign("sha256", Buffer.from(`${header}.${arr}`), {
    key: privateKey, dsaEncoding: "ieee-p1363",
  });
  assert.equal(verifyJwt(`${header}.${arr}.${sig2.toString("base64url")}`, base), null);
});

test("getKey 沒給（設定不全）→ fail-closed", () => {
  assert.equal(verifyJwt(valid(), { requiredClaims: { app: APP } }), null);
  assert.equal(verifyJwt(valid(), {}), null);
});

test("algorithms 白名單：沒列進去的 alg 擋掉", () => {
  const es384 = keypair("secp384r1");
  const token = signToken({ sub: "u1", app: APP, exp: future() }, { key: es384.privateKey, alg: "ES384" });
  const getEs384 = () => es384.publicKey;
  // 預設只收 ES256 → ES384 的 token 擋掉
  assert.equal(verifyJwt(token, { getKey: getEs384, requiredClaims: { app: APP } }), null);
  // 明確允許才通
  assert.notEqual(
    verifyJwt(token, { getKey: getEs384, requiredClaims: { app: APP }, algorithms: ["ES384"] }),
    null,
  );
  // 允許 ES384 之後,ES256 的 token 就不該再通（白名單是白名單）
  assert.equal(verifyJwt(valid(), { ...base, algorithms: ["ES384"] }), null);
});

test("verifyJwtAsync 行為與同步版一致,且吞掉 getKey 的例外", async () => {
  assert.notEqual(await verifyJwtAsync(valid(), { ...base, getKey: async (k) => getKey(k) }), null);
  assert.equal(await verifyJwtAsync(valid({ app: "other" }), { ...base, getKey: async (k) => getKey(k) }), null);
  assert.equal(await verifyJwtAsync(valid(), { ...base, getKey: async () => { throw new Error("boom"); } }), null);
});

test("bearerToken：RFC 6750 的 scheme 不分大小寫", () => {
  assert.equal(bearerToken("Bearer abc"), "abc");
  assert.equal(bearerToken("bearer abc"), "abc");
  assert.equal(bearerToken("BEARER\tabc"), "abc");
  assert.equal(bearerToken("  Bearer   abc  "), "abc");
  assert.equal(bearerToken("Basic abc"), null);
  assert.equal(bearerToken("Bearer"), null);
  assert.equal(bearerToken("Bearer   "), null);
  assert.equal(bearerToken(null), null);
  assert.equal(bearerToken(undefined), null);
});

// ── review 後補上的（2026-11-08 security + code review）──────────────────────

test("🔒 requiredClaims 型別錯誤 → fail-closed（不是跳過檢查）", () => {
  // `required && typeof required === "object"` 這種寫法會讓「忘了 JSON.parse
  // 的字串」整個檢查消失,而且測試照樣全綠。
  const token = valid({ app: "app_OTHER" });
  for (const bad of ['{"app":"app_test"}', 1, true, () => {}, ["app_test"]]) {
    assert.equal(verifyJwt(token, { getKey, requiredClaims: bad }), null, JSON.stringify(String(bad)));
  }
  // 正常的物件照常比對
  assert.equal(verifyJwt(token, base), null);
  assert.notEqual(verifyJwt(valid(), base), null);
});

test("🔒 allowedClaims 型別錯誤或空清單 → fail-closed", () => {
  const token = valid();
  assert.notEqual(verifyJwt(token, { getKey, allowedClaims: { app: [APP, "x"] } }), null);
  assert.equal(verifyJwt(token, { getKey, allowedClaims: { app: [] } }), null, "空清單");
  assert.equal(verifyJwt(token, { getKey, allowedClaims: { app: APP } }), null, "不是陣列");
  assert.equal(verifyJwt(token, { getKey, allowedClaims: "app" }), null, "不是物件");
  assert.equal(verifyJwt(valid({ app: "other" }), { getKey, allowedClaims: { app: [APP] } }), null);
});

test("🔒 原型鏈：缺少的 claim 不得從 Object.prototype 解析到值", () => {
  // 行程裡任何一處 prototype pollution ＋ 一顆沒有 exp / 沒有 app 的合法簽章
  // token ＝ 永不過期、任何租戶都通。claims 必須是 null-prototype。
  const noExpNoApp = signToken({ sub: "attacker" }, { key: privateKey });
  assert.equal(verifyJwt(noExpNoApp, base), null, "污染前就該拒絕");
  // eslint-disable-next-line no-extend-native
  Object.prototype.exp = future();
  // eslint-disable-next-line no-extend-native
  Object.prototype.app = APP;
  try {
    assert.equal(verifyJwt(noExpNoApp, base), null, "污染後仍必須拒絕");
  } finally {
    delete Object.prototype.exp;
    delete Object.prototype.app;
  }
});

test("🔒 payload 帶 own __proto__ / constructor key → 整顆拒絕", () => {
  // JSON.parse 會把 __proto__ 做成真的 own data property。宿主只要做過
  // `Object.assign(session, claims)` 就會觸發目標原型上的 setter
  //（`{...claims}` 安全,Object.assign 不安全）。IdP 沒有理由發這種 claim。
  const payload = `{"sub":"u1","app":"${APP}","exp":${future()},"__proto__":{"isAdmin":true}}`;
  assert.equal(verifyJwt(signRawPayload(payload, { key: privateKey }), base), null);
  const ctor = `{"sub":"u1","app":"${APP}","exp":${future()},"constructor":{"x":1}}`;
  assert.equal(verifyJwt(signRawPayload(ctor, { key: privateKey }), base), null);
  // 對照組：一般 claim 照常通過
  const fine = `{"sub":"u1","app":"${APP}","exp":${future()},"role":"admin"}`;
  assert.notEqual(verifyJwt(signRawPayload(fine, { key: privateKey }), base), null);
});

test("🔒 簽章段必須是正規化的 base64url（86 字元有 4 個自由位元 → 16 種等價寫法）", () => {
  // 編碼層的等價寫法全部驗得過的話,任何以 token 字串當 key 的東西（撤銷黑
  // 名單、重放/idempotency 快取、限流桶、log 去重）都能被繞過。
  const token = valid();
  const [h, p, s] = token.split(".");
  assert.notEqual(verifyJwt(token, base), null, "正規寫法要通");
  const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let variants = 0;
  let accepted = 0;
  for (const ch of ALPHABET) {
    const mutated = s.slice(0, 85) + ch;
    if (mutated === s) continue;
    // 只看「解碼後位元組完全相同」的那些（真正的非正規寫法）
    if (!Buffer.from(mutated, "base64url").equals(Buffer.from(s, "base64url"))) continue;
    variants += 1;
    if (verifyJwt(`${h}.${p}.${mutated}`, base) !== null) accepted += 1;
  }
  assert.ok(variants >= 15, `應該找到至少 15 種等價寫法,實際 ${variants}`);
  assert.equal(accepted, 0, `等價寫法必須全部拒絕,實際放行 ${accepted} 個`);
});

test("🔒 header 帶 crit 一律拒絕（RFC 7515：不理解的擴充必須拒收）", () => {
  const token = signToken({ sub: "u1", app: APP, exp: future() },
    { key: privateKey, header: { crit: ["unknown-ext"] } });
  assert.equal(verifyJwt(token, base), null);
});

test("🔒 sub 必須是非空字串（預設開啟；SKILL.md 的稽核清單本來就要求）", () => {
  for (const bad of [{ a: 1 }, ["x"], 42, "", null, true]) {
    assert.equal(
      verifyJwt(signToken({ sub: bad, app: APP, exp: future() }, { key: privateKey }), base),
      null,
      JSON.stringify(bad),
    );
  }
  assert.equal(verifyJwt(signToken({ app: APP, exp: future() }, { key: privateKey }), base), null, "缺 sub");
  // 可以明確關掉（非 LetMeUse 的 IdP 也許真的不發 sub）
  const noSub = signToken({ app: APP, exp: future() }, { key: privateKey });
  assert.notEqual(verifyJwt(noSub, { ...base, requireSubject: false }), null);
});

test("requiredClaims 對陣列型 claim 比對成員（標準 aud 常是陣列）", () => {
  const token = signToken({ sub: "u1", aud: ["my-api", "other"], exp: future() }, { key: privateKey });
  assert.notEqual(verifyJwt(token, { getKey, requiredClaims: { aud: "my-api" } }), null);
  assert.equal(verifyJwt(token, { getKey, requiredClaims: { aud: "nope" } }), null);
});

test("algorithms 型別錯誤 → fail-closed（不默默退回 ES256）", () => {
  const token = valid();
  for (const bad of ["ES256", [], [""], [1], {}]) {
    assert.equal(verifyJwt(token, { ...base, algorithms: bad }), null, JSON.stringify(bad));
  }
});

test("verifyJwtAsync 沒給 getKey → null", async () => {
  assert.equal(await verifyJwtAsync(valid(), { requiredClaims: { app: APP } }), null);
});

test("🔒 陣列成員比對只適用 aud —— 租戶 claim 必須嚴格相等", () => {
  // 一顆 app: ["app_test","app_other"] 的 token 若因「集合包含」而通過,就能
  // 同時通過兩個租戶的驗證,而且它是簽名有效的真 token,沒有任何線索。
  const multiApp = signToken({ sub: "u1", app: [APP, "app_other"], exp: future() }, { key: privateKey });
  assert.equal(verifyJwt(multiApp, base), null, "陣列型 app 不得通過");
  // allowedClaims 方向相反,但同樣 fail-closed
  assert.equal(verifyJwt(multiApp, { getKey, allowedClaims: { app: [APP] } }), null);
  // aud 仍然做成員比對（RFC 7519 §4.1.3）
  const multiAud = signToken({ sub: "u1", aud: ["my-api", "other"], exp: future() }, { key: privateKey });
  assert.notEqual(verifyJwt(multiAud, { getKey, requiredClaims: { aud: "my-api" } }), null);
  // 但 aud 陣列裡混入非字串 → 拒絕
  const weirdAud = signToken({ sub: "u1", aud: ["my-api", { x: 1 }], exp: future() }, { key: privateKey });
  assert.equal(verifyJwt(weirdAud, { getKey, requiredClaims: { aud: "my-api" } }), null);
});
