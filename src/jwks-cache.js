// JWKS 公鑰快取。
//
// 為什麼要快取：驗簽是同步的，抓 JWKS 是非同步的。背景抓好放進 Map，驗證時
// 同步讀 —— 不讓每個請求都去打一次 IdP。
//
// 🔒 fail-closed：抓不到金鑰時 getKey 回 null，驗證一律失敗。寧可拒絕真使用者
// 也不放行偽造 token。但 **fail-closed 必須看得見** —— 所以有 onError 與
// stats()，而 onError 的預設值是 `console.error` 而不是 noop：預設安靜等於
// 「IdP 一掛就全部 401 且零線索」，那正是這個檔要避免的事。

const crypto = require("node:crypto");
const { CRV_TO_ALG } = require("./algorithms");

const DEFAULT_REFRESH_MS = 60 * 60 * 1000; // JWKS 通常回 max-age=3600
const DEFAULT_MISS_COOLDOWN_MS = 60 * 1000; // kid 沒中（可能剛輪換）→ 最快 60 秒重抓
const DEFAULT_TIMEOUT_MS = 5000;
// 連續抓不到這麼久之後，寧可全部拒絕也不要拿「不知道多舊」的公鑰繼續放行。
// 給得寬鬆（一天）：IdP 短暫停機不該讓所有人當場失效。
const DEFAULT_MAX_STALE_MS = 24 * 60 * 60 * 1000;
// 手動 refresh() 的最小間隔，**預設關閉（0）**。
//
// 原本預設 3000ms，而且節流到的時候靜默回一個已 resolve 的 promise。那讓
// 「金鑰外洩 → 從 JWKS 下架 → 呼叫 refresh() 立刻生效」這條路變成無聲 no-op,
// 也就是這個 kit 一開始就說要消滅的那種 fail-open。權衡過後選擇預設不節流：
//   - 併發風暴已經由 in-flight 合流擋掉（N 個同時呼叫 = 一次抓取）
//   - 連續呼叫必須 await 上一個，本身就被限制成一次一個來回
//   - 真正的放大風險來自「宿主把 refresh 接到公開端點」，那是宿主該限流的事
//     （ratelimit-kit），不該用一個會靜默吃掉緊急撤銷的預設值來代償
// 要那道閘就自己設 minRefreshIntervalMs，而且記得看 refresh() 的回傳值 ——
// 現在節流到會回 `{ throttled: true }`，不再假裝成功。
const DEFAULT_MIN_REFRESH_INTERVAL_MS = 0;
// JWKS 正常只有個位數把金鑰。上限存在的理由是 `createPublicKey` 不便宜：
// 實測兩萬把會讓 event loop 阻塞 1.2 秒，而且每次刷新都重來一遍。
const DEFAULT_MAX_KEYS = 50;
const WHEN_IDLE_MAX_HOPS = 10;

/**
 * JWK → KeyObject。只收得起 EC 簽章公鑰，其餘回 null（跳過，不害整批）。
 * 第二個回傳值是「跳過的原因」，給呼叫端決定要不要大聲報。
 */
function toPublicKey(jwk, allowedAlgs) {
  if (!jwk || typeof jwk !== "object") return [null, "不是物件"];
  if (typeof jwk.kid !== "string" || !jwk.kid) return [null, "沒有 kid"];
  if (jwk.kty !== "EC") return [null, `kty=${jwk.kty} 不是 EC`];
  // 🔒 JWKS 裡出現私鑰材料（EC 的 `d`）表示 IdP 正在洩漏它的簽章金鑰。這個
  // kit 是唯一站在能發現它的位置上的元件 —— 大聲報出來，而不是默默當公鑰用。
  if (jwk.d !== undefined) return [null, `kid=${jwk.kid} 的 JWK 含私鑰材料（d）—— IdP 正在洩漏簽章金鑰！`];
  const impliedAlg = CRV_TO_ALG[jwk.crv];
  if (!impliedAlg) return [null, `crv=${jwk.crv} 不支援`];
  // JWK 自己宣告的 alg 要跟曲線一致，且在宿主允許的白名單內
  if (jwk.alg && jwk.alg !== impliedAlg) return [null, `kid=${jwk.kid} 的 alg 與曲線不符`];
  if (Array.isArray(allowedAlgs) && allowedAlgs.length > 0 && !allowedAlgs.includes(impliedAlg)) {
    return [null, null]; // 不在白名單內是正常過濾，不用報
  }
  if (jwk.use && jwk.use !== "sig") return [null, null]; // 加密用的金鑰不拿來驗簽
  if (Array.isArray(jwk.key_ops) && !jwk.key_ops.includes("verify")) return [null, null];
  try {
    return [crypto.createPublicKey({ key: jwk, format: "jwk" }), null];
  } catch (err) {
    return [null, `kid=${jwk.kid} 載入失敗：${err.message}`];
  }
}

/**
 * 加上逾時。
 *
 * ⚠️ 這不是多餘的保險：**node 的 fetch 沒有預設逾時**。對方「接了連線但永遠
 * 不回」時 promise 永不 settle → inFlight 旗標永遠卡住 → 快取再也不會更新、
 * 每個請求都 401 直到重啟，而且零診斷。AbortSignal 負責真的中止網路，這層
 * race 則保證就算注入的 fetchImpl 不理 signal，inFlight 也一定會放掉。
 */
function withTimeout(promise, ms) {
  if (!(ms > 0)) return promise;
  return new Promise((resolve, reject) => {
    // 刻意不 unref()：unref 的計時器在「沒有其他事情撐著 event loop」時不會
    // 觸發，卡死的 fetch 就永遠等不到逾時（寫測試時直接現形）。它一旦 fetch
    // 回來就被 clear，只有真的逾時才存在，最多延後 process 結束 ms 毫秒。
    const timer = setTimeout(() => reject(new Error(`JWKS fetch timed out after ${ms}ms`)), ms);
    promise.then(
      (value) => { clearTimeout(timer); resolve(value); },
      (err) => { clearTimeout(timer); reject(err); },
    );
  });
}

/**
 * @param {{
 *   url: string,
 *   algorithms?: string[],
 *   fetchImpl?: Function,
 *   refreshMs?: number,              // 0 = 不做定時刷新
 *   missCooldownMs?: number,
 *   minRefreshIntervalMs?: number,   // 手動 refresh() 的節流
 *   timeoutMs?: number,              // 0 = 不加逾時（只應在測試裡關掉）
 *   maxStaleMs?: number,             // 0 = 不做 stale fail-closed
 *   maxKeys?: number,
 *   onError?: (err: Error) => void,  // 預設 console.error
 * }} options
 */
function createJwksCache(options = {}) {
  const url = options.url || "";
  const algorithms = options.algorithms;
  const fetchImpl = options.fetchImpl || ((...args) => globalThis.fetch(...args));
  const refreshMs = options.refreshMs != null ? options.refreshMs : DEFAULT_REFRESH_MS;
  const missCooldownMs = options.missCooldownMs != null ? options.missCooldownMs : DEFAULT_MISS_COOLDOWN_MS;
  const minRefreshIntervalMs = options.minRefreshIntervalMs != null
    ? options.minRefreshIntervalMs
    : DEFAULT_MIN_REFRESH_INTERVAL_MS;
  const timeoutMs = options.timeoutMs != null ? options.timeoutMs : DEFAULT_TIMEOUT_MS;
  const maxStaleMs = options.maxStaleMs != null ? options.maxStaleMs : DEFAULT_MAX_STALE_MS;
  const maxKeys = options.maxKeys != null ? options.maxKeys : DEFAULT_MAX_KEYS;
  // 預設大聲：安靜的 fail-closed 就是無聲故障
  const onError = typeof options.onError === "function"
    ? options.onError
    : (err) => { console.error("[jwks-verify-kit]", err.message); };

  let keysByKid = new Map();
  let lastAttemptAt = 0;
  let lastSuccessAt = 0;
  let lastMissFetchAt = 0;
  let lastError = null;
  let lastMissKid = null;
  let inFlight = null;
  let timer = null;

  function report(err) {
    lastError = err;
    try {
      onError(err);
    } catch (ignored) {
      // reporter 自己壞掉不該炸這裡
    }
  }

  async function doRefresh() {
    try {
      if (!url) throw new Error("jwks-verify-kit: 沒有設定 JWKS 網址（fail-closed）");
      const signal = timeoutMs > 0 && typeof AbortSignal !== "undefined"
        && typeof AbortSignal.timeout === "function"
        ? AbortSignal.timeout(timeoutMs)
        : undefined;
      // redirect: "error" —— JWKS 回應**就是**信任根，一個 302 等於無聲把它
      // 搬到別的主機去。寧可壞掉也不要跟著跳。
      const init = { redirect: "error", ...(signal ? { signal } : {}) };
      // 單一期限：fetch 與 res.json() 共用同一個預算。各給一次完整逾時的話,
      // 慢速 IdP 可以讓走 getKeyAsync 的請求卡 2×timeoutMs（預設 10 秒）。
      const deadline = timeoutMs > 0 ? Date.now() + timeoutMs : 0;
      const remaining = () => (deadline > 0 ? Math.max(1, deadline - Date.now()) : 0);
      const res = await withTimeout(fetchImpl(url, init), remaining());
      if (!res || !res.ok) throw new Error(`JWKS HTTP ${res ? res.status : "no response"}`);
      const data = await withTimeout(Promise.resolve(res.json()), remaining());
      if (!data || !Array.isArray(data.keys)) {
        throw new Error("JWKS 回應格式不正確（keys 不是陣列）");
      }
      if (maxKeys > 0 && data.keys.length > maxKeys) {
        report(new Error(
          `JWKS 回了 ${data.keys.length} 把金鑰，超過上限 ${maxKeys} —— 只取前 ${maxKeys} 把`
          + "（createPublicKey 不便宜，大量金鑰會阻塞 event loop）",
        ));
      }
      const slice = maxKeys > 0 ? data.keys.slice(0, maxKeys) : data.keys;
      const next = new Map();
      for (const jwk of slice) {
        const [key, reason] = toPublicKey(jwk, algorithms);
        if (reason) report(new Error(`JWKS: ${reason}`));
        if (!key) continue;
        // 重複 kid 取**第一筆**。「惡意項目附加在合法 JWKS 後面」是現實形狀，
        // last-wins 會讓後面那筆靜默覆蓋掉真的金鑰。
        if (next.has(jwk.kid)) {
          report(new Error(`JWKS 有重複的 kid=${jwk.kid} —— 保留第一筆，忽略後面的`));
          continue;
        }
        next.set(jwk.kid, key);
      }
      // 🔒 格式正確的 200 就是權威答案，**即使 keys 是空的**，所以整批換掉。
      // 「空的不覆蓋舊快取」看似保守，實際會讓緊急撤銷永遠不生效：IdP 私鑰
      // 外洩、把金鑰從 JWKS 下架之後，這邊卻還拿著舊公鑰繼續放行被盜金鑰簽
      // 的 token，直到有人想起來重啟 —— 而這種 process 會活好幾週。
      // 真正該保留舊快取的只有「傳輸層失敗」，那些路徑在上面就 throw 了。
      keysByKid = next;
      lastSuccessAt = Date.now();
      lastError = null;
      if (next.size === 0) {
        report(new Error("JWKS 沒有任何可用的公鑰 —— 快取已清空，所有 token 會被拒絕"));
      }
    } catch (e) {
      // 網路/解析失敗 → 保留舊快取，不往外拋（呼叫端是背景任務，沒人 catch），
      // 但一定要讓外面看得到
      report(e);
    }
  }

  /**
   * 抓一次 JWKS。併發呼叫共用同一個 in-flight promise。
   * `force` 由內部的定時刷新/預熱使用，會跳過最小間隔節流。
   *
   * 回傳 `{ refreshed, throttled, coalesced, keys }` —— **不是只有 void**。
   *
   * ⚠️ 2026-11-08 修：節流原本預設 3000ms 且**靜默回一個已 resolve 的
   * promise**，所以宿主 `await cache.refresh()` 之後以為抓過了，其實什麼都沒
   * 發生。這在正常情況無傷，但它踩爛的正是這個 kit 存在的理由之一：
   * 「LetMeUse 私鑰外洩 → 把金鑰從 JWKS 下架 → 呼叫 refresh() 立刻生效」。
   * 那個路徑一旦靜默 no-op，被盜金鑰簽的 token 會繼續通行到有人重啟 process。
   *
   * 兩件事一起改：
   *   1. **預設不節流**（`minRefreshIntervalMs` 預設 0）。併發已經靠 in-flight
   *      合流擋住風暴了；連續呼叫必須 await 上一個，本身就是一次一回合。
   *   2. 真的節流到的時候**告訴呼叫端**（`throttled: true`），不要再靜默。
   * 要擋「把 refresh 接到公開端點」的放大效果，請自己設
   * `minRefreshIntervalMs` 或在端點前面加限流（ratelimit-kit），並檢查回傳值。
   *
   * 這個 bug 之所以躲過 81 個測試：kit 自己的測試把節流全域設成 0，於是從來
   * 沒有任何測試跑在預設值上 —— 預設值要有自己的測試。
   */
  function refresh(force = false) {
    if (inFlight) return inFlight.then(() => ({ refreshed: true, throttled: false, coalesced: true, keys: keysByKid.size }));
    if (!force && minRefreshIntervalMs > 0 && lastAttemptAt > 0
      && Date.now() - lastAttemptAt < minRefreshIntervalMs) {
      return Promise.resolve({ refreshed: false, throttled: true, coalesced: false, keys: keysByKid.size });
    }
    inFlight = doRefresh().finally(() => {
      inFlight = null;
      // 冷卻從「結束」算起：慢速或逾時的抓取若從開始算，等於完全沒冷卻
      lastAttemptAt = Date.now();
    });
    return inFlight.then(() => ({ refreshed: true, throttled: false, coalesced: false, keys: keysByKid.size }));
  }

  function isStale() {
    return maxStaleMs > 0 && lastSuccessAt > 0 && Date.now() - lastSuccessAt > maxStaleMs;
  }

  /**
   * 未知 kid（可能剛輪換）→ 在背景補抓一次，但有獨立冷卻。
   * 回 { promise, started }：`started` 才代表「這次 miss 真的發動了抓取」，
   * getKeyAsync 只在那種情況下才等 —— 否則 500 個帶亂 kid 的匿名請求會全部
   * 掛在同一個 in-flight fetch 上（serverless 按時間計費，那是放大器）。
   */
  function kickBackgroundRefresh() {
    if (inFlight) return { promise: inFlight, started: false };
    if (Date.now() - lastMissFetchAt < missCooldownMs) return { promise: null, started: false };
    // 先卡住，擋掉一波未知 kid 同時湧進來；結束時再蓋一次（見下）
    lastMissFetchAt = Date.now();
    // 冷卻用獨立的 lastMissFetchAt，不跟定時刷新共用 —— 共用的話，剛跑完的
    // 定時刷新會把冷卻洗掉，金鑰輪換要等整個 cooldown 才跟得上。
    const promise = refresh(true).finally(() => { lastMissFetchAt = Date.now(); });
    return { promise, started: true };
  }

  /**
   * 同步取公鑰。kid 不在快取裡就順手在背景重抓，但「這一次」仍回 null ——
   * 驗簽必須同步，而 fail-closed 比等網路安全。
   *
   * ⚠️ 代價：重啟後的「第一個」請求就算帶完全有效的 token 也會被拒絕（快取
   * 還空的）。所以宿主一定要在開機時 `await verifier.ready()`；做不到的環境
   * （例如 Next.js 可能把 instrumentation 和 route handler 打包成不同 module
   * 實例，預熱到的是另一份快取）請改用 getKeyAsync。
   */
  function getKey(kid) {
    if (typeof kid !== "string" || !kid) return null;
    const key = isStale() ? undefined : keysByKid.get(kid);
    if (!key) {
      lastMissKid = kid;
      kickBackgroundRefresh();
    }
    return key || null;
  }

  /**
   * 非同步取公鑰：**這次 miss 真的發動了抓取**時才等它，然後再答。
   * 這樣重啟後第一個請求就能成功，而後續的未知 kid 不會集體排隊。
   * 最壞情況約 2×timeoutMs（fetch 與 res.json() 各有一層逾時）。
   */
  async function getKeyAsync(kid) {
    if (typeof kid !== "string" || !kid) return null;
    const cached = isStale() ? undefined : keysByKid.get(kid);
    if (cached) return cached;
    lastMissKid = kid;
    const { promise, started } = kickBackgroundRefresh();
    if (started && promise) await promise;
    return (isStale() ? undefined : keysByKid.get(kid)) || null;
  }

  /** 診斷用狀態：給 /health 與 log 用，別讓 fail-closed 變成無聲故障。 */
  function stats() {
    return {
      url,
      keys: keysByKid.size,
      // kid 是公開資訊。放進來是因為最常見的事故形狀是「輪換後 token 的 kid
      // 不在快取裡」,而單一個數字分不出它跟健康快取的差別。
      kids: [...keysByKid.keys()],
      lastMissKid,
      stale: isStale(),
      lastSuccessAt: lastSuccessAt || null,
      lastAttemptAt: lastAttemptAt || null,
      lastError: lastError ? lastError.message : null,
    };
  }

  /** 等背景那次抓取結束。有上限，免得未來改壞變成無聲掛住。 */
  async function whenIdle() {
    for (let i = 0; i < WHEN_IDLE_MAX_HOPS && inFlight; i += 1) {
      await inFlight;
    }
  }

  /** 開機：抓一次並回傳該 promise（宿主該 await 它），之後定時刷新。 */
  function start() {
    const first = refresh(true);
    if (refreshMs > 0 && !timer) {
      timer = setInterval(() => refresh(true), refreshMs);
      if (typeof timer.unref === "function") timer.unref(); // 不卡住 process 結束
    }
    return first;
  }

  function stop() {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
  }

  return { getKey, getKeyAsync, refresh, whenIdle, stats, start, stop, url };
}

module.exports = { createJwksCache };
