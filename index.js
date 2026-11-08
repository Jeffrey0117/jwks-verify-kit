// ============================================================================
// jwks-verify-kit — 當消費端，驗別人家 IdP 發的非對稱 JWT（公鑰走 JWKS）
// ----------------------------------------------------------------------------
// 零依賴（只用 node 內建 crypto）。**不發 token** —— 要自己發 session 用 auth-kit。
//
// 為什麼需要它、每個 fail-open 的來歷、以及接線時的地雷：見 README.md 與 SKILL.md。
// 這裡只放 API。
//
//   const auth = createLetMeUseVerifier({ appId: process.env.LETMEUSE_APP_ID });
//   await auth.ready();
//   const claims = auth.verifySync(auth.bearer(req.headers.authorization));
//   if (!claims) return res.writeHead(401).end();
//
// ⚠️ 非同步版叫 `verifyAsync`，刻意**沒有**叫 `verify`：忘記 await 的話
// `if (!claims)` 會拿到一個 truthy 的 Promise → 當成已驗證放行。短而順手的
// 名字不該是那顆地雷，所以乾脆不提供。
// ============================================================================

const { createJwksCache } = require("./src/jwks-cache");
const { verifyJwt, verifyJwtAsync, bearerToken } = require("./src/verify");
const { SUPPORTED_ALGS, DEFAULT_ALGS } = require("./src/algorithms");
const { num, plainObjectOrNull, freezeCopy } = require("./src/options");

/**
 * 拼出並檢查 JWKS 網址。刻意不內建任何主機 —— 位址一律由宿主注入。
 *
 * 🔒 強制 https（localhost 例外）：JWKS 回應**就是**信任根。一個 `http://`
 * 的手誤就讓同網段上任何人換掉公鑰、替任何使用者簽 token —— 一個字元換來
 * 完整的認證繞過。要真的用明文得明確寫 `allowInsecureHttp: true`。
 */
function resolveUrl(options) {
  const raw = options.jwksUrl
    ? String(options.jwksUrl)
    : (() => {
      const base = String(options.baseUrl || "").replace(/\/+$/, "");
      if (!base) return "";
      const path = options.jwksPath || "/.well-known/jwks.json";
      return base + (path.startsWith("/") ? path : `/${path}`);
    })();

  if (!raw) return "";
  if (options.jwksUrl !== undefined && typeof options.jwksUrl !== "string") {
    throw new Error(`jwks-verify-kit: jwksUrl 必須是字串（收到 ${typeof options.jwksUrl}）`);
  }

  let parsed;
  try {
    parsed = new URL(raw);
  } catch (e) {
    throw new Error(`jwks-verify-kit: JWKS 網址無效：${JSON.stringify(raw)}`);
  }
  const localhost = ["localhost", "127.0.0.1", "[::1]", "::1"].includes(parsed.hostname);
  const insecureOk = options.allowInsecureHttp === true || (parsed.protocol === "http:" && localhost);
  if (parsed.protocol !== "https:" && !insecureOk) {
    throw new Error(
      `jwks-verify-kit: JWKS 必須走 https（收到 ${parsed.protocol}//${parsed.hostname}）。`
      + "這個回應就是信任根 —— 明文等於任何中間人都能換掉公鑰、替任何使用者簽 token。"
      + "真的要明文請明確傳 allowInsecureHttp: true。",
    );
  }
  return raw;
}

function resolveAlgorithms(options) {
  if (options.algorithms === undefined || options.algorithms === null) return DEFAULT_ALGS.slice();
  if (!Array.isArray(options.algorithms) || options.algorithms.length === 0
    || !options.algorithms.every((a) => typeof a === "string" && a)) {
    throw new Error(
      `jwks-verify-kit: algorithms 必須是非空的字串陣列（收到 ${JSON.stringify(options.algorithms)}）。`
      + '寫成 algorithms: "ES384"（忘了包陣列）會變成「所有真的 ES384 token 全被拒絕且零解釋」。',
    );
  }
  for (const alg of options.algorithms) {
    if (!SUPPORTED_ALGS.includes(alg)) {
      // 大聲壞掉：悄悄忽略一個不支援的 alg，宿主會以為它被接受了
      throw new Error(
        `jwks-verify-kit: 不支援的 algorithm "${alg}"（支援：${SUPPORTED_ALGS.join(", ")}）`,
      );
    }
  }
  return options.algorithms.slice();
}

/**
 * 建一個驗證器。
 *
 * @param {{
 *   jwksUrl?: string, baseUrl?: string, jwksPath?: string,
 *   allowInsecureHttp?: boolean,
 *   algorithms?: string[],
 *   issuer?: string,
 *   requiredClaims?: Record<string, unknown>,
 *   allowedClaims?: Record<string, unknown[]>,
 *   requireSubject?: boolean,
 *   clockToleranceSec?: number,
 *   refreshMs?: number, missCooldownMs?: number, minRefreshIntervalMs?: number,
 *   timeoutMs?: number, maxStaleMs?: number, maxKeys?: number,
 *   fetchImpl?: Function,
 *   onError?: (err: Error) => void,
 *   autoStart?: boolean,
 * }} options
 */
function createJwksVerifier(options = {}) {
  const url = resolveUrl(options);
  const algorithms = resolveAlgorithms(options);

  const cache = createJwksCache({
    url,
    algorithms,
    fetchImpl: options.fetchImpl,
    refreshMs: num("refreshMs", options.refreshMs, undefined),
    missCooldownMs: num("missCooldownMs", options.missCooldownMs, undefined),
    minRefreshIntervalMs: num("minRefreshIntervalMs", options.minRefreshIntervalMs, undefined),
    timeoutMs: num("timeoutMs", options.timeoutMs, undefined),
    maxStaleMs: num("maxStaleMs", options.maxStaleMs, undefined),
    maxKeys: num("maxKeys", options.maxKeys, undefined),
    onError: options.onError,
  });

  // 凍結拷貝：宿主之後改動它傳進來的物件不該改變驗證結果
  const verifyOpts = Object.freeze({
    algorithms: Object.freeze(algorithms),
    issuer: options.issuer,
    requiredClaims: freezeCopy(plainObjectOrNull("requiredClaims", options.requiredClaims)),
    allowedClaims: freezeCopy(plainObjectOrNull("allowedClaims", options.allowedClaims)),
    requireSubject: options.requireSubject !== false, // 預設要求非空字串 sub
    clockToleranceSec: num("clockToleranceSec", options.clockToleranceSec, 0),
    // 逐顆 token 的拒絕原因。沒給就完全不收集（零成本）。
    // 一個只會回 null 的驗證器在出事時查不動 ——「使用者說他登不進去」而伺服器
    // 只知道 401，到底是過期、kid 還沒輪換進快取、還是 app claim 不符？
    // ⚠️ info 裡的值多半是呼叫端送來的，寫自己的 log 沒問題，**別回給呼叫端**。
    onReject: typeof options.onReject === "function" ? options.onReject : undefined,
  });

  let started = null;

  /**
   * 同步驗證 → claims 或 null。快取 miss 時 fail-closed（背景補抓）。
   * 刻意沒有「每次呼叫覆寫選項」的第二參數：淺層 spread 會讓呼叫端把建構時
   * 設好的 requiredClaims / issuer / exp 檢查整個換掉，而那正是這個 kit 要
   * 消滅的 fail-open。要逐路由加條件，請另建一個 verifier。
   */
  function verifySync(token) {
    return verifyJwt(token, { ...verifyOpts, getKey: cache.getKey });
  }

  /**
   * 非同步驗證：快取 miss 時等一次（有逾時的）抓取，所以重啟後第一個請求
   * 也會成功。在無法保證開機預熱的環境（Next.js / serverless）用這支。
   */
  function verifyAsync(token) {
    return verifyJwtAsync(token, { ...verifyOpts, getKey: cache.getKeyAsync });
  }

  /**
   * 開機預熱：等第一次 JWKS 抓取完成，回傳 stats()。
   *
   * ⚠️ 它在 IdP 掛掉時**也會 resolve**（抓取失敗是記錄下來、不往外拋），所以
   * 別把「resolve 了」讀成「金鑰載好了」—— 看回傳的 `keys`。要讓它在失敗時
   * 直接 reject，傳 `{ strict: true }`。
   */
  async function ready(opts) {
    if (!started) started = cache.start();
    await started;
    const s = cache.stats();
    if (opts && opts.strict && !s.lastSuccessAt) {
      throw new Error(`jwks-verify-kit: JWKS 預熱失敗（${s.lastError || "原因不明"}）`);
    }
    return s;
  }

  /** 收掉定時器。之後再 ready() 會重新裝回去（忘記這點會讓刷新永久消失）。 */
  function stop() {
    started = null;
    cache.stop();
  }

  if (options.autoStart !== false) ready();

  return {
    verifySync,
    verifyAsync,
    bearer: bearerToken,
    ready,
    stop,
    refresh: cache.refresh,
    whenIdle: cache.whenIdle,
    stats: cache.stats,
    getKey: cache.getKey,
    getKeyAsync: cache.getKeyAsync,
    jwksUrl: url,
  };
}

/**
 * LetMeUse 專用預設（Jeff 生態系）。
 *
 * 跟泛用版的差別都是實際踩過的坑：
 *   1. jwksPath 預設 `/api/jwks`（LetMeUse 不走標準的 .well-known）
 *   2. **appId 必填，缺了就 throw**。LetMeUse 用同一把 ES256 金鑰簽發所有
 *      app 的 token，所以 `app` claim 是唯一的租戶邊界。少了它不是「少一道
 *      檢查」，而是「任何 LetMeUse app 的任何使用者都能進來」。
 *   3. **網址也必填**。缺網址的驗證器會變成「永遠拒絕每一顆 token」，而服務
 *      本身回 200、健檢全綠、沒人登入得進來，統計是 0 看起來像還沒人用
 *      —— areyoubot 就這樣跑了三個月。設定不全要在啟動時就壞。
 *   4. 網址與 appId 可從 env 取，但**明確傳入的參數優先**（env 蓋掉明確參數
 *      會讓「我傳了 baseUrl 卻連到別處」這種事無法 debug）。
 */
function createLetMeUseVerifier(options = {}) {
  const trim = (v) => (typeof v === "string" ? v.trim() : v);
  // env 值可能帶 CRLF 尾巴（.env 檔或 cloudpipe env API 很容易產生）。
  // 不 trim 的話 appId 會比不中 → 每顆真 token 都被拒絕，而 stats() 一片健康。
  const appId = trim(options.appId !== undefined ? options.appId : process.env.LETMEUSE_APP_ID);
  if (typeof appId !== "string" || !appId) {
    throw new Error(
      "jwks-verify-kit: createLetMeUseVerifier 需要 appId（LetMeUse 所有 app 共用同一把簽章金鑰，"
      + "app claim 是唯一的租戶邊界 —— 沒有它等於接受任何 app 的使用者）。"
      + "請傳 appId 或設 LETMEUSE_APP_ID。",
    );
  }

  // 明確傳入優先；兩個都沒給才看 env
  const explicitUrl = trim(options.jwksUrl) || "";
  const explicitBase = trim(options.baseUrl) || "";
  const jwksUrl = explicitUrl || (explicitBase ? "" : trim(process.env.LETMEUSE_JWKS_URL) || "");
  const baseUrl = explicitBase || (explicitUrl ? "" : trim(process.env.LETMEUSE_BASE_URL) || "");
  if (!jwksUrl && !baseUrl) {
    throw new Error(
      "jwks-verify-kit: createLetMeUseVerifier 需要 jwksUrl 或 baseUrl（或 LETMEUSE_JWKS_URL /"
      + " LETMEUSE_BASE_URL）。沒有網址的驗證器會永遠拒絕每一顆 token，而服務照樣回 200"
      + "、健檢全綠 —— 那種故障最難查。",
    );
  }

  return createJwksVerifier({
    ...options,
    jwksUrl,
    baseUrl,
    jwksPath: options.jwksPath || "/api/jwks",
    // app 放在最後：宿主不該能覆寫這個 kit 剛剛才說「唯一的租戶邊界」的那個 claim
    requiredClaims: { ...(options.requiredClaims || {}), app: appId },
  });
}

module.exports = {
  createJwksVerifier,
  createLetMeUseVerifier,
  // 低階積木：想自己管快取 / 只要純驗證時用
  createJwksCache,
  verifyJwt,
  verifyJwtAsync,
  bearerToken,
  SUPPORTED_ALGS,
};
