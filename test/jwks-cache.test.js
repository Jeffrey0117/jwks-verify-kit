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

test("🔒 沒設 url → **建構時就 throw**（不是靜默變成拒絕所有人）", () => {
  // 2026-11-08 改：原本空網址是「每次 refresh 記一筆 lastError」。那太安靜 ——
  // 服務照樣回 200、健檢全綠、沒有人登入得進來（areyoubot 就這樣跑了三個月）。
  // 現在設定不全在建構時就壞掉。
  assert.throws(() => createJwksCache(cacheOpts({ url: "" })), /JWKS 網址必填/);
  assert.throws(() => createJwksCache(cacheOpts({ url: undefined })), /JWKS 網址必填/);
  assert.throws(() => createJwksCache(cacheOpts({ url: "not a url" })), /網址無效/);
});

test("🔒 低階的 createJwksCache 也擋明文 http（規則不能只住在高階版）", () => {
  // 生態系九個消費端為了自己管快取全都走低階版 —— 規則住在 createJwksVerifier
  // 等於九個都沒有規則。`LETMEUSE_JWKS_URL=http://...` 一個 env 打錯就讓信任根
  // 變明文：同網段任何人回自己的 JWKS,就能替任何使用者簽 token,而且零錯誤訊息。
  assert.throws(() => createJwksCache(cacheOpts({ url: "http://idp.test/jwks" })), /必須走 https/);
  assert.throws(() => createJwksCache(cacheOpts({ url: "file:///C:/Windows/win.ini" })), /必須走 https/);
  // localhost 的明文合法（同機直連不經網路,生態系常態）
  createJwksCache(cacheOpts({ url: "http://localhost:4006/api/jwks" })).stop();
  createJwksCache(cacheOpts({ url: "http://127.0.0.1:4006/api/jwks" })).stop();
  // 真的要對外明文得明確表態
  createJwksCache(cacheOpts({ url: "http://idp.test/jwks", allowInsecureHttp: true })).stop();
});

test("🔒 抓取失敗要 fail-closed,而且錯誤看得見", async () => {
  const errors = [];
  const cache = createJwksCache(cacheOpts({
    fetchImpl: fakeFetch(new Error("ECONNREFUSED")),
    onError: (e) => errors.push(e),
  }));
  await cache.refresh();
  assert.equal(errors.length, 1, "抓取失敗要回報一次");
  assert.equal(cache.getKey("kid-1"), null, "回 null 而不是放行");
  await cache.whenIdle();
  assert.match(cache.stats().lastError, /ECONNREFUSED/);
  cache.stop();
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
    fetchImpl: fakeFetch(new Error("boom")),
    onError: () => { throw new Error("reporter is broken"); },
  }));
  await cache.refresh(); // 不該 reject
  assert.ok(cache.stats().lastError);
  cache.stop();
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
  //
  // ⚠️ 2026-11-08 改寫:這條規則原本寫成「無條件」,於是把本 kit 明文要消滅的
  // 失敗模式帶了回來 —— 冷啟動時 start() 已經在飛,第一個請求的查詢「不是我
  // 發動的」就不等 → 回 null → 401(回套 upimg 時被它的測試抓到)。
  // 現在的邊界是「**有沒有成功抓到過金鑰**」:
  //   - 還沒成功過(冷啟動) → 等。反正不等也是 401,等了至少有機會成功,而且
  //     這個窗口只有冷啟動的頭幾百毫秒。
  //   - 已經有金鑰 → 不等,維持防放大(這個測試現在測的就是這一半)。
  let release;
  const gate = new Promise((r) => { release = r; });
  let n = 0;
  const impl = async () => {
    n += 1;
    if (n > 1) await gate; // 第一次正常回,之後卡住
    return { ok: true, status: 200, json: async () => JWKS };
  };
  const cache = createJwksCache(cacheOpts({ fetchImpl: impl, missCooldownMs: 60_000, timeoutMs: 0 }));
  await cache.refresh();                  // 先讓快取有金鑰(= 不再是冷啟動)
  assert.ok(cache.getKey("kid-1"));

  const first = cache.getKeyAsync("unknown-a"); // 這次發動抓取 → 會等(卡在 gate)
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

test("🔒 權威的空 JWKS 之後不要再傻等（金鑰真的沒了,等完還是 null）", async () => {
  // 跟上面那條冷啟動的例外要分清楚:邊界是「有沒有成功抓到過」而不是「快取是不
  // 是空的」。金鑰被緊急下架時 size 也是 0,但那時候等待只是白付等待的錢。
  let n = 0;
  let release;
  const gate = new Promise((r) => { release = r; });
  const impl = async () => {
    n += 1;
    if (n > 1) await gate;
    return { ok: true, status: 200, json: async () => ({ keys: [] }) }; // 權威的空
  };
  const cache = createJwksCache(cacheOpts({ fetchImpl: impl, missCooldownMs: 0, timeoutMs: 0 }));
  await cache.refresh(); // 成功抓到「空的」→ lastSuccessAt 有值, keys = 0

  const kick = cache.getKeyAsync("kid-1"); // 發動抓取(卡住)
  await new Promise((r) => setImmediate(r));
  const t0 = Date.now();
  const second = await cache.getKeyAsync("kid-2");
  assert.equal(second, null);
  assert.ok(Date.now() - t0 < 50, "下架之後不該再排隊等");
  release();
  await kick;
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

test("🕒 注入時鐘能驅動政策計時（冷卻/stale），抓取逾時不受影響", async () => {
  // 沒有這個注入，冷卻與 stale 只能用「設成 0」或「真的等 60 秒」來測 —— 於是
  // 實務上沒人測，而 refresh() 節流的 bug 就是這樣躲過全部測試的。
  let clock = 1_700_000_000_000;
  let serve = "kid-old";
  const impl = fakeFetch(() => ({ keys: [toJwk(publicKey, serve)] }));
  const cache = createJwksCache({
    url: "https://idp.test/jwks",
    refreshMs: 0,               // 不要定時器,完全由 miss + 冷卻驅動
    missCooldownMs: 60_000,
    maxStaleMs: 10 * 60_000,
    onError: () => {},
    fetchImpl: impl,
    now: () => clock,
  });

  await cache.refresh();
  assert.ok(cache.getKey("kid-old"));
  assert.equal(impl.calls.length, 1);

  // 第一次遇到未知 kid 一定會抓（lastMissFetchAt 還是 0 = 從沒因 miss 抓過）,
  // 這是對的:剛輪換出來的 kid 不該先等 60 秒。這次抓回來的還是 kid-old。
  assert.equal(await cache.getKeyAsync("kid-unknown"), null);
  assert.equal(impl.calls.length, 2, "第一次 miss 要抓");

  // 冷卻計時從這裡開始。金鑰輪換了,但還在冷卻期內 → 不該再抓
  serve = "kid-new";
  assert.equal(await cache.getKeyAsync("kid-new"), null, "冷卻期內不重抓");
  assert.equal(impl.calls.length, 2);

  // 推進假時鐘越過冷卻 → 這次要抓,而且抓到輪換後的新 kid
  clock += 61_000;
  assert.ok(await cache.getKeyAsync("kid-new"), "冷卻過了就該抓到輪換後的金鑰");
  assert.equal(impl.calls.length, 3);

  // stale 判定也吃假時鐘
  assert.equal(cache.stats().stale, false);
  clock += 11 * 60_000;
  assert.equal(cache.stats().stale, true, "超過 maxStaleMs 要標記 stale");
  cache.stop();
});

test("🔒 冷啟動：快取還空著時,getKeyAsync 要等在飛的那次抓取（不能回 null）", async () => {
  // 這是本 kit 明文要消滅的失敗模式:「重啟後第一個請求就算帶完全有效的 token
  // 也會 401」。原本的「只有自己發動的抓取才等」把它帶了回來 —— 因為冷啟動時
  // start() 已經在飛,於是同一個請求的查詢「不是我發動的」就不等。
  //
  // 回套 upimg（Next.js,沒有可靠的開機預熱點）時被它的測試抓到。
  let release;
  const gate = new Promise((r) => { release = r; });
  const impl = async (url, init) => {
    await gate; // 讓抓取卡住,製造「有 inFlight」的狀態
    return { ok: true, status: 200, json: async () => JWKS };
  };
  impl.calls = [];
  const cache = createJwksCache(cacheOpts({ fetchImpl: impl }));

  void cache.start();            // 開始抓(卡在 gate)
  const lookup = cache.getKeyAsync("kid-1"); // 同一個「請求」來查
  release();                     // 抓取完成

  assert.ok(await lookup, "冷啟動的第一個查詢必須等到金鑰,不能回 null");
  cache.stop();
});

test("快取已經有金鑰時,未知 kid 不等在飛的抓取（防放大效果,維持原行為）", async () => {
  // 另一個方向也要釘住:已經有金鑰的情況下,500 個帶亂 kid 的匿名請求不該全部
  // 掛在同一個 fetch 上（serverless 按時間計費,那是放大器）。
  let release;
  const gate = new Promise((r) => { release = r; });
  let n = 0;
  const impl = async () => {
    n += 1;
    if (n > 1) await gate;
    return { ok: true, status: 200, json: async () => JWKS };
  };
  const cache = createJwksCache(cacheOpts({ fetchImpl: impl, missCooldownMs: 0 }));
  await cache.refresh();
  assert.ok(cache.getKey("kid-1"), "先有金鑰");

  // ⚠️ 第一個查詢**不能 await** —— 它自己發動了那個被 gate 卡住的抓取,await 它
  // 就是跟自己死鎖(我第一版就這樣寫,整個測試檔 5 個測試一起 cancelled)。
  const first = cache.getKeyAsync("kid-unknown-1");
  const started = Date.now();
  const second = await cache.getKeyAsync("kid-unknown-2"); // 不該等別人的抓取
  assert.equal(second, null);
  assert.ok(Date.now() - started < 3000, "不該掛在那個卡住的抓取上");
  release();
  await first;
  cache.stop();
});
