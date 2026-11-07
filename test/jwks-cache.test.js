const test = require("node:test");
const assert = require("node:assert/strict");

const { createJwksCache } = require("../src/jwks-cache");
const { keypair, toJwk, fakeFetch } = require("./helpers");

const { publicKey } = keypair();
const JWKS = { keys: [toJwk(publicKey, "kid-1")] };

const cacheOpts = (extra = {}) => ({
  url: "https://idp.test/jwks",
  refreshMs: 0, // 測試裡不要定時器
  ...extra,
});

test("抓到金鑰後 getKey 同步取得", async () => {
  const cache = createJwksCache(cacheOpts({ fetchImpl: fakeFetch(JWKS) }));
  await cache.refresh();
  assert.ok(cache.getKey("kid-1"));
  assert.equal(cache.getKey("kid-nope"), null);
  assert.equal(cache.stats().keys, 1);
  assert.equal(cache.stats().lastError, null);
});

test("🔒 沒設 url → fail-closed,且錯誤看得見", async () => {
  const errors = [];
  const cache = createJwksCache(cacheOpts({ url: "", onError: (e) => errors.push(e) }));
  await cache.refresh();
  assert.equal(errors.length, 1, "抓取失敗要回報一次");
  // getKey 的 miss 會再觸發一次背景重抓（那也會失敗並回報）—— 這是對的,
  // 重點是它回 null 而不是放行
  assert.equal(cache.getKey("kid-1"), null);
  await cache.whenIdle();
  assert.match(cache.stats().lastError, /JWKS 網址/);
});

test("🔒 格式正確的空 JWKS 要清空快取（否則緊急撤銷永遠不生效）", async () => {
  let payload = JWKS;
  const cache = createJwksCache(cacheOpts({ fetchImpl: fakeFetch(() => payload) }));
  await cache.refresh();
  assert.ok(cache.getKey("kid-1"), "先有金鑰");

  // IdP 私鑰外洩 → 把金鑰從 JWKS 下架
  payload = { keys: [] };
  await cache.refresh();
  assert.equal(cache.getKey("kid-1"), null, "撤銷後必須拒絕");
  assert.equal(cache.stats().keys, 0);
  assert.match(cache.stats().lastError, /沒有任何可用的公鑰/);
});

test("傳輸層失敗則保留舊快取（這才是該保守的情況）", async () => {
  let fail = false;
  const impl = async () => {
    if (fail) throw new Error("ECONNREFUSED");
    return { ok: true, status: 200, json: async () => JWKS };
  };
  const cache = createJwksCache(cacheOpts({ fetchImpl: impl }));
  await cache.refresh();
  fail = true;
  await cache.refresh();
  assert.ok(cache.getKey("kid-1"), "IdP 暫時掛掉不該讓所有人當場失效");
  assert.match(cache.stats().lastError, /ECONNREFUSED/);
});

test("HTTP 非 2xx 不覆蓋快取", async () => {
  const cache = createJwksCache(cacheOpts({ fetchImpl: fakeFetch(JWKS, { ok: false, status: 503 }) }));
  await cache.refresh();
  assert.equal(cache.getKey("kid-1"), null);
  assert.match(cache.stats().lastError, /HTTP 503/);
});

test("keys 不是陣列 → 當成格式錯誤,不覆蓋", async () => {
  const cache = createJwksCache(cacheOpts({ fetchImpl: fakeFetch({ keys: "nope" }) }));
  await cache.refresh();
  assert.match(cache.stats().lastError, /格式不正確/);
});

test("🔒 卡死的 fetch 會逾時,而且 in-flight 旗標要放掉（否則快取永久凍結）", async () => {
  // node 的 fetch 沒有預設逾時。對方接了連線卻永不回應時,如果沒有這層保護,
  // promise 永不 settle → inFlight 永遠占住 → 快取再也不更新,每個請求都 401
  // 直到重啟,而且零診斷。
  let settled = false;
  const stalled = () => new Promise(() => {}); // 永遠不 resolve
  const cache = createJwksCache(cacheOpts({ fetchImpl: stalled, timeoutMs: 50 }));
  const p = cache.refresh().then(() => { settled = true; });
  await p;
  assert.equal(settled, true, "refresh 一定要結束");
  assert.match(cache.stats().lastError, /timed out/);

  // 關鍵：逾時之後還能再抓,而且這次會成功（旗標真的放掉了）
  const cache2 = createJwksCache(cacheOpts({ fetchImpl: stalled, timeoutMs: 50 }));
  await cache2.refresh();
  // 換成正常的 fetch 再抓一次
  const working = createJwksCache(cacheOpts({ fetchImpl: fakeFetch(JWKS) }));
  await working.refresh();
  assert.ok(working.getKey("kid-1"));
});

test("併發 refresh 共用同一次抓取", async () => {
  const impl = fakeFetch(JWKS);
  const cache = createJwksCache(cacheOpts({ fetchImpl: impl }));
  await Promise.all([cache.refresh(), cache.refresh(), cache.refresh()]);
  assert.equal(impl.calls.length, 1);
});

test("未知 kid 觸發背景重抓,但有冷卻", async () => {
  const impl = fakeFetch(JWKS);
  const cache = createJwksCache(cacheOpts({ fetchImpl: impl, missCooldownMs: 10_000 }));
  await cache.refresh();
  assert.equal(impl.calls.length, 1);

  cache.getKey("rotated-kid"); // miss → 背景抓
  await cache.whenIdle();
  assert.equal(impl.calls.length, 2);

  cache.getKey("rotated-kid"); // 冷卻中 → 不再抓
  cache.getKey("another-kid");
  await cache.whenIdle();
  assert.equal(impl.calls.length, 2, "冷卻期內不該連續打 IdP");
});

test("未知 kid 的冷卻與定時刷新分開計（金鑰輪換才跟得上）", async () => {
  const impl = fakeFetch(JWKS);
  const cache = createJwksCache(cacheOpts({ fetchImpl: impl, missCooldownMs: 0 }));
  await cache.refresh(); // 模擬「定時刷新剛跑完」
  cache.getKey("rotated-kid");
  await cache.whenIdle();
  assert.equal(impl.calls.length, 2, "定時刷新不該把 miss 冷卻洗掉");
});

test("🔒 太久沒成功更新 → 當作沒有金鑰（不拿不知多舊的公鑰繼續放行）", async () => {
  const cache = createJwksCache(cacheOpts({ fetchImpl: fakeFetch(JWKS), maxStaleMs: 1 }));
  await cache.refresh();
  assert.ok(cache.getKey("kid-1"));
  await new Promise((r) => setTimeout(r, 5));
  assert.equal(cache.getKey("kid-1"), null);
  assert.equal(cache.stats().stale, true);
});

test("JWK 篩選：非 EC、加密用途、曲線與 alg 不符的一律跳過", async () => {
  const rsa = require("node:crypto").generateKeyPairSync("rsa", { modulusLength: 2048 });
  const payload = {
    keys: [
      { ...rsa.publicKey.export({ format: "jwk" }), kid: "rsa", use: "sig" },
      toJwk(publicKey, "enc-key", { use: "enc" }),
      toJwk(publicKey, "wrong-alg", { alg: "ES512" }),
      toJwk(publicKey, "no-verify", { key_ops: ["deriveKey"] }),
      { kid: "", kty: "EC", crv: "P-256" },
      toJwk(publicKey, "good"),
    ],
  };
  const cache = createJwksCache(cacheOpts({ fetchImpl: fakeFetch(payload) }));
  await cache.refresh();
  assert.equal(cache.stats().keys, 1);
  assert.ok(cache.getKey("good"));
  for (const bad of ["rsa", "enc-key", "wrong-alg", "no-verify"]) {
    assert.equal(cache.getKey(bad), null, bad);
  }
});

test("getKeyAsync：冷快取時等一次抓取就能成功（重啟後第一個請求）", async () => {
  const impl = fakeFetch(JWKS);
  const cache = createJwksCache(cacheOpts({ fetchImpl: impl, missCooldownMs: 0 }));
  // 完全沒預熱
  assert.equal(cache.getKey("kid-1"), null, "同步版在冷快取時 fail-closed");
  const cache2 = createJwksCache(cacheOpts({ fetchImpl: fakeFetch(JWKS), missCooldownMs: 0 }));
  assert.ok(await cache2.getKeyAsync("kid-1"), "非同步版應該等得到");
});

test("getKey / getKeyAsync 對壞 kid 不 throw", async () => {
  const cache = createJwksCache(cacheOpts({ fetchImpl: fakeFetch(JWKS) }));
  await cache.refresh();
  for (const bad of [null, undefined, "", 42, {}]) {
    assert.equal(cache.getKey(bad), null);
    assert.equal(await cache.getKeyAsync(bad), null);
  }
});

test("onError 自己壞掉不該炸快取", async () => {
  const cache = createJwksCache(cacheOpts({
    url: "",
    onError: () => { throw new Error("reporter is broken"); },
  }));
  await cache.refresh(); // 不該 reject
  assert.ok(cache.stats().lastError);
});

test("start() 回第一次抓取的 promise,stop() 收掉定時器", async () => {
  const impl = fakeFetch(JWKS);
  const cache = createJwksCache(cacheOpts({ fetchImpl: impl, refreshMs: 50 }));
  await cache.start();
  assert.ok(cache.getKey("kid-1"), "await start() 之後就該是暖的");
  cache.stop();
});
