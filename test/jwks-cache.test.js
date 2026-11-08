const test = require("node:test");
const assert = require("node:assert/strict");

const { createJwksCache } = require("../src/jwks-cache");
const { keypair, toJwk, fakeFetch } = require("./helpers");

const { publicKey } = keypair();
const JWKS = { keys: [toJwk(publicKey, "kid-1")] };

const cacheOpts = (extra = {}) => ({
  url: "https://idp.test/jwks",
  refreshMs: 0,              // 測試裡不要定時器
  minRefreshIntervalMs: 0,   // 手動 refresh 的節流在測試裡關掉（另有專門測試）
  onError: () => {},         // 預設是 console.error,測試裡別噴滿螢幕
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

// ── review 後補上的（2026-11-08）────────────────────────────────────────────

test("手動 refresh() 設了最小間隔就會節流，但**會講**（不再靜默假裝成功）", async () => {
  const impl = fakeFetch(JWKS);
  const cache = createJwksCache(cacheOpts({ fetchImpl: impl, minRefreshIntervalMs: 60_000 }));
  const first = await cache.refresh();
  assert.equal(first.refreshed, true);
  assert.equal(first.throttled, false);
  for (let i = 0; i < 20; i += 1) {
    const r = await cache.refresh();
    // 這一行是重點：節流掉的時候呼叫端拿得到 throttled:true。原本是回
    // `undefined`，宿主 `await refresh()` 後完全無法分辨「抓過了」與「被吃掉」。
    assert.equal(r.throttled, true, "節流要回報，不能靜默");
    assert.equal(r.refreshed, false);
  }
  assert.equal(impl.calls.length, 1, "節流後只該有第一次");
  // 內部的定時刷新/預熱走 force,不受節流影響
  await cache.start();
  assert.equal(impl.calls.length, 2);
  cache.stop();
});

test("🔒 預設不節流手動 refresh()，否則緊急撤銷金鑰會被無聲吃掉", async () => {
  // 劇本（這個 kit 存在的理由之一）：IdP 私鑰外洩 → 把金鑰從 JWKS 下架 →
  // 宿主呼叫 refresh() 要它立刻生效。預設值一旦節流又靜默，被盜金鑰簽的
  // token 會繼續通行到有人想起來重啟 process。
  //
  // ⚠️ 刻意**不用** cacheOpts()：這個檔案的共用選項把 minRefreshIntervalMs
  // 設成 0，所以 81 個測試從來沒有一個跑在預設值上 —— 這個 bug 就是這樣躲過
  // 全部測試的（靠真實消費端 speakslow-stats 的既有測試才掉出來）。
  const impl = fakeFetch((n) => (n === 1 ? { keys: [toJwk(publicKey, "leaked-kid")] } : { keys: [] }));
  const cache = createJwksCache({
    url: "https://idp.test/jwks",
    refreshMs: 0,
    onError: () => {},
    fetchImpl: impl,
    // minRefreshIntervalMs 刻意不給 → 走預設值
  });

  await cache.refresh();
  assert.ok(cache.getKey("leaked-kid"), "第一次抓到外洩的那把");

  const second = await cache.refresh(); // 權威的空回應（金鑰已下架）
  assert.equal(second.throttled, false, "預設不該節流");
  assert.equal(impl.calls.length, 2, "第二次 refresh 必須真的發出請求");
  assert.equal(cache.getKey("leaked-kid"), null, "被撤銷的金鑰必須立刻失效");
  cache.stop();
});

test("🔒 JWKS 金鑰數有上限（createPublicKey 不便宜,兩萬把會阻塞 event loop）", async () => {
  const many = { keys: Array.from({ length: 200 }, (_, i) => toJwk(publicKey, `k${i}`)) };
  const errors = [];
  const cache = createJwksCache(cacheOpts({
    fetchImpl: fakeFetch(many), maxKeys: 10, onError: (e) => errors.push(e.message),
  }));
  await cache.refresh();
  assert.equal(cache.stats().keys, 10);
  assert.ok(errors.some((m) => /超過上限/.test(m)), "超量要大聲報");
});

test("🔒 JWKS 裡出現私鑰材料（d）→ 拒收該把並大聲報（IdP 正在洩漏簽章金鑰）", async () => {
  const { privateKey: pk } = keypair();
  const leaky = { keys: [{ ...pk.export({ format: "jwk" }), kid: "leaked", use: "sig" }, toJwk(publicKey, "good")] };
  const errors = [];
  const cache = createJwksCache(cacheOpts({ fetchImpl: fakeFetch(leaky), onError: (e) => errors.push(e.message) }));
  await cache.refresh();
  assert.equal(cache.getKey("leaked"), null);
  assert.ok(cache.getKey("good"));
  assert.ok(errors.some((m) => /私鑰材料/.test(m)), "要明確指出 IdP 在洩漏私鑰");
});

test("🔒 重複 kid 取第一筆（惡意項目附加在合法 JWKS 後面是現實形狀）", async () => {
  const attacker = keypair();
  const payload = { keys: [toJwk(publicKey, "dup"), toJwk(attacker.publicKey, "dup")] };
  const errors = [];
  const cache = createJwksCache(cacheOpts({ fetchImpl: fakeFetch(payload), onError: (e) => errors.push(e.message) }));
  await cache.refresh();
  const got = cache.getKey("dup");
  assert.ok(got);
  assert.equal(
    got.export({ format: "jwk" }).x,
    publicKey.export({ format: "jwk" }).x,
    "必須是第一筆（真的那把）,不是被後面覆蓋",
  );
  assert.ok(errors.some((m) => /重複的 kid/.test(m)));
});

test("fetch 帶 redirect:error（JWKS 是信任根,302 等於無聲搬家）", async () => {
  const impl = fakeFetch(JWKS);
  const cache = createJwksCache(cacheOpts({ fetchImpl: impl }));
  await cache.refresh();
  assert.equal(impl.calls[0].init.redirect, "error");
});

test("曲線不在 algorithms 白名單內的金鑰會被過濾掉", async () => {
  const p384 = keypair("secp384r1");
  const payload = { keys: [toJwk(p384.publicKey, "k384"), toJwk(publicKey, "k256")] };
  const cache = createJwksCache(cacheOpts({ fetchImpl: fakeFetch(payload), algorithms: ["ES256"] }));
  await cache.refresh();
  assert.equal(cache.getKey("k384"), null);
  assert.ok(cache.getKey("k256"));
});

test("壞掉的 JWK（createPublicKey 丟錯）會被跳過並報出來", async () => {
  const payload = { keys: [{ kty: "EC", crv: "P-256", kid: "bad", x: "!!!", y: "!!!" }, toJwk(publicKey, "ok")] };
  const errors = [];
  const cache = createJwksCache(cacheOpts({ fetchImpl: fakeFetch(payload), onError: (e) => errors.push(e.message) }));
  await cache.refresh();
  assert.equal(cache.getKey("bad"), null);
  assert.ok(cache.getKey("ok"));
  assert.ok(errors.some((m) => /載入失敗/.test(m)));
});

test("stats() 帶 kids 與 lastMissKid（輪換事故靠數字看不出來）", async () => {
  const cache = createJwksCache(cacheOpts({ fetchImpl: fakeFetch(JWKS), missCooldownMs: 60_000 }));
  await cache.refresh();
  assert.deepEqual(cache.stats().kids, ["kid-1"]);
  assert.equal(cache.stats().lastMissKid, null);
  cache.getKey("rotated-kid-9");
  await cache.whenIdle();
  assert.equal(cache.stats().lastMissKid, "rotated-kid-9");
});

test("getKeyAsync 在冷卻期內不排隊等別人的抓取（serverless 計費放大）", async () => {
  // 500 個帶亂 kid 的匿名請求若全掛在同一個 in-flight fetch 上,等於每個請求
  // 都被計費等待。只有「真的發動抓取」的那次才該等。
  let release;
  const gate = new Promise((r) => { release = r; });
  const impl = async () => {
    await gate;
    return { ok: true, status: 200, json: async () => JWKS };
  };
  const cache = createJwksCache(cacheOpts({ fetchImpl: impl, missCooldownMs: 60_000, timeoutMs: 0 }));
  const first = cache.getKeyAsync("unknown-a"); // 這次發動抓取 → 會等
  await new Promise((r) => setImmediate(r));
  const t0 = Date.now();
  const second = await cache.getKeyAsync("unknown-b"); // 冷卻中 → 不該等
  const elapsed = Date.now() - t0;
  assert.equal(second, null);
  assert.ok(elapsed < 50, `第二個請求不該排隊,實際等了 ${elapsed}ms`);
  release();
  await first;
  cache.stop();
});

test("timeoutMs 共用單一期限（不是 fetch 與 json 各給一次）", async () => {
  // 兩段各給完整逾時的話,慢速 IdP 可以讓一個請求卡 2×timeoutMs。
  const impl = async () => ({
    ok: true,
    status: 200,
    json: () => new Promise(() => {}), // json 永遠不 resolve
  });
  const cache = createJwksCache(cacheOpts({ fetchImpl: impl, timeoutMs: 120 }));
  const t0 = Date.now();
  await cache.refresh();
  const elapsed = Date.now() - t0;
  assert.match(cache.stats().lastError, /timed out/);
  assert.ok(elapsed < 240, `總預算該是 ~120ms 而非 240ms,實際 ${elapsed}ms`);
});
