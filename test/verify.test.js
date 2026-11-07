const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const { verifyJwt, verifyJwtAsync, bearerToken } = require("../src/verify");
const { keypair, signToken, signHs256, nowSec } = require("./helpers");

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
