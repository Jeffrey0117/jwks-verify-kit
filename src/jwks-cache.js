// JWKS 公鑰快取。
//
// 為什麼要快取：驗簽是同步的，抓 JWKS 是非同步的。背景抓好放進 Map，驗證時
// 同步讀 —— 不讓每個請求都去打一次 IdP。
//
// 🔒 fail-closed：抓不到金鑰時 getKey 回 null，驗證一律失敗。寧可拒絕真使用者
// 也不放行偽造 token。但 **fail-closed 必須看得見** —— 所以有 onError 與
// stats()，讓宿主能印 log、把狀態掛上 /health。不然 IdP 一掛就是「全部 401
// 且零診斷」，查三小時都查不到。

const crypto = require("node:crypto");
const { CRV_TO_ALG } = require("./algorithms");

const DEFAULT_REFRESH_MS = 60 * 60 * 1000; // JWKS 通常回 max-age=3600
const DEFAULT_MISS_COOLDOWN_MS = 60 * 1000; // kid 沒中（可能剛輪換）→ 最快 60 秒重抓
const DEFAULT_TIMEOUT_MS = 5000;
// 連續抓不到這麼久之後，寧可全部拒絕也不要拿「不知道多舊」的公鑰繼續放行。
// 給得寬鬆（一天）：IdP 短暫停機不該讓所有人當場失效。
const DEFAULT_MAX_STALE_MS = 24 * 60 * 60 * 1000;
const WHEN_IDLE_MAX_HOPS = 10;

/** JWK → KeyObject。只收得起 EC 簽章金鑰，其餘回 null（跳過，不害整批）。 */
function toPublicKey(jwk, allowedAlgs) {
  if (!jwk || typeof jwk !== "object") return null;
  if (typeof jwk.kid !== "string" || !jwk.kid) return null;
  if (jwk.kty !== "EC") return null;
  const impliedAlg = CRV_TO_ALG[jwk.crv];
  if (!impliedAlg) return null;
  // JWK 自己宣告的 alg 要跟曲線一致，且在宿主允許的白名單內
  if (jwk.alg && jwk.alg !== impliedAlg) return null;
  if (Array.isArray(allowedAlgs) && allowedAlgs.length > 0 && !allowedAlgs.includes(impliedAlg)) {
    return null;
  }
  if (jwk.use && jwk.use !== "sig") return null; // 加密用的金鑰不拿來驗簽
  if (Array.isArray(jwk.key_ops) && !jwk.key_ops.includes("verify")) return null;
  try {
    return crypto.createPublicKey({ key: jwk, format: "jwk" });
  } catch (e) {
    return null;
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
 *   refreshMs?: number,       // 0 = 不做定時刷新
 *   missCooldownMs?: number,
 *   timeoutMs?: number,       // 0 = 不加逾時（只應在測試裡關掉）
 *   maxStaleMs?: number,      // 0 = 不做 stale fail-closed
 *   onError?: (err: Error) => void,
 * }} options
 */
function createJwksCache(options = {}) {
  const url = options.url || "";
  const algorithms = options.algorithms;
  const fetchImpl = options.fetchImpl || ((...args) => globalThis.fetch(...args));
  const refreshMs = options.refreshMs != null ? options.refreshMs : DEFAULT_REFRESH_MS;
  const missCooldownMs = options.missCooldownMs != null ? options.missCooldownMs : DEFAULT_MISS_COOLDOWN_MS;
  const timeoutMs = options.timeoutMs != null ? options.timeoutMs : DEFAULT_TIMEOUT_MS;
  const maxStaleMs = options.maxStaleMs != null ? options.maxStaleMs : DEFAULT_MAX_STALE_MS;
  const onError = typeof options.onError === "function" ? options.onError : () => {};

  let keysByKid = new Map();
  let lastAttemptAt = 0;
  let lastSuccessAt = 0;
  let lastMissFetchAt = 0;
  let lastError = null;
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
      const res = await withTimeout(fetchImpl(url, signal ? { signal } : undefined), timeoutMs);
      if (!res || !res.ok) throw new Error(`JWKS HTTP ${res ? res.status : "no response"}`);
      const data = await withTimeout(Promise.resolve(res.json()), timeoutMs);
      if (!data || !Array.isArray(data.keys)) {
        throw new Error("JWKS 回應格式不正確（keys 不是陣列）");
      }
      const next = new Map();
      for (const jwk of data.keys) {
        const key = toPublicKey(jwk, algorithms);
        if (key) next.set(jwk.kid, key);
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

  /** 抓一次 JWKS。併發呼叫共用同一個 in-flight promise。 */
  function refresh() {
    if (inFlight) return inFlight;
    inFlight = doRefresh().finally(() => {
      inFlight = null;
      // 冷卻從「結束」算起：慢速或逾時的抓取若從開始算，等於完全沒冷卻
      lastAttemptAt = Date.now();
    });
    return inFlight;
  }

  function isStale() {
    return maxStaleMs > 0 && lastSuccessAt > 0 && Date.now() - lastSuccessAt > maxStaleMs;
  }

  /** 未知 kid（可能剛輪換）→ 在背景補抓一次，但有獨立冷卻。 */
  function kickBackgroundRefresh() {
    if (inFlight) return inFlight;
    if (Date.now() - lastMissFetchAt < missCooldownMs) return null;
    // 先卡住，擋掉一波未知 kid 同時湧進來；結束時再蓋一次（見下）
    lastMissFetchAt = Date.now();
    // 冷卻用獨立的 lastMissFetchAt，不跟定時刷新共用 —— 共用的話，剛跑完的
    // 定時刷新會把冷卻洗掉，金鑰輪換要等整個 cooldown 才跟得上。
    return refresh().finally(() => { lastMissFetchAt = Date.now(); });
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
    if (!key) kickBackgroundRefresh();
    return key || null;
  }

  /**
   * 非同步取公鑰：miss 時**等**一次有上限的抓取再回答。
   * 這樣重啟後第一個請求就能成功，代價是該請求多等一次 JWKS 往返（有逾時）。
   */
  async function getKeyAsync(kid) {
    if (typeof kid !== "string" || !kid) return null;
    const cached = isStale() ? undefined : keysByKid.get(kid);
    if (cached) return cached;
    const pending = kickBackgroundRefresh();
    if (pending) await pending;
    return (isStale() ? undefined : keysByKid.get(kid)) || null;
  }

  /** 診斷用狀態：給 /health 與 log 用，別讓 fail-closed 變成無聲故障。 */
  function stats() {
    return {
      url,
      keys: keysByKid.size,
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
    const first = refresh();
    if (refreshMs > 0 && !timer) {
      timer = setInterval(refresh, refreshMs);
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
