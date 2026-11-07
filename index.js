// ============================================================================
// jwks-verify-kit — 驗「別人家 IdP」發的非對稱 JWT，公鑰走 JWKS
// ----------------------------------------------------------------------------
// 零依賴（只用 node 內建 crypto）。不是用來發 token 的 —— 要自己發 session 請
// 用 auth-kit。這個 kit 專門做一件事：**當消費端**，驗證某個外部身分提供者
// （LetMeUse、Auth0、Clerk、Keycloak…）簽的 access token。
//
// 為什麼要有這個 kit（它解決的不是「少寫幾行」）：
//
//   對稱簽章（HS256）的致命問題是「驗證方必須握著簽發金鑰」。app secret 一
//   外洩，任何人都能自簽一顆 sub/role 隨便填的 token 冒充任何人 —— 包含管理
//   員。改成非對稱（ES256）之後，驗證方只需要公鑰，**那台機器可以完全不存
//   任何 secret**；就算 secret 早就洩了，偽造的 token 一樣進不來。
//
//   而「驗 ES256 + JWKS」這件事看起來簡單、實際上有十幾個會靜默 fail-open
//   的角落（alg 白名單、kid 必填、exp 型別、租戶 claim、空 JWKS 要不要覆蓋、
//   fetch 沒有預設逾時、未知 kid 的冷卻、重啟後第一個請求…）。每個專案自己
//   寫一份 = 每個專案各自踩一半。這個 kit 就是那一份。
//
// 用法（最短）：
//   const { createLetMeUseVerifier } = require('jwks-verify-kit');
//   const auth = createLetMeUseVerifier({ appId: process.env.LETMEUSE_APP_ID });
//   await auth.ready();                       // 開機預熱（很重要，見 SKILL.md）
//   const claims = auth.verifySync(auth.bearer(req.headers.authorization));
//   if (!claims) return res.writeHead(401).end();
//
// 泛用版（任何 IdP）：
//   const auth = createJwksVerifier({
//     jwksUrl: 'https://idp.example.com/.well-known/jwks.json',
//     issuer: 'https://idp.example.com',
//     requiredClaims: { aud: 'my-api' },
//   });
// ============================================================================

const { createJwksCache } = require("./src/jwks-cache");
const { verifyJwt, verifyJwtAsync, bearerToken } = require("./src/verify");
const { SUPPORTED_ALGS } = require("./src/algorithms");

/** 拼出 JWKS 網址。刻意不內建任何主機 —— 位址一律由宿主注入。 */
function resolveUrl(opts) {
  if (opts.jwksUrl) return String(opts.jwksUrl);
  const base = String(opts.baseUrl || "").replace(/\/+$/, "");
  if (!base) return "";
  const path = opts.jwksPath || "/.well-known/jwks.json";
  return base + (path.startsWith("/") ? path : `/${path}`);
}

/**
 * 建一個驗證器。
 *
 * @param {{
 *   jwksUrl?: string,                 // 完整 JWKS 網址（優先）
 *   baseUrl?: string,                 // 或給 base，與 jwksPath 組合
 *   jwksPath?: string,                // 預設 /.well-known/jwks.json
 *   algorithms?: string[],            // 預設 ["ES256"]
 *   issuer?: string,                  // 給了就比對 iss
 *   requiredClaims?: Record<string, unknown>, // 必須完全相等的 claim（租戶邊界）
 *   clockToleranceSec?: number,       // 預設 0
 *   refreshMs?: number, missCooldownMs?: number,
 *   timeoutMs?: number, maxStaleMs?: number,
 *   fetchImpl?: Function,
 *   onError?: (err: Error) => void,
 *   autoStart?: boolean,              // 預設 true：建好就開始抓並定時刷新
 * }} options
 */
function createJwksVerifier(options = {}) {
  const url = resolveUrl(options);
  const algorithms = Array.isArray(options.algorithms) && options.algorithms.length > 0
    ? options.algorithms.slice()
    : ["ES256"];

  for (const alg of algorithms) {
    if (!SUPPORTED_ALGS.includes(alg)) {
      // 大聲壞掉：悄悄忽略一個不支援的 alg，宿主會以為它被接受了
      throw new Error(
        `jwks-verify-kit: 不支援的 algorithm "${alg}"（支援：${SUPPORTED_ALGS.join(", ")}）`,
      );
    }
  }

  const cache = createJwksCache({
    url,
    algorithms,
    fetchImpl: options.fetchImpl,
    refreshMs: options.refreshMs,
    missCooldownMs: options.missCooldownMs,
    timeoutMs: options.timeoutMs,
    maxStaleMs: options.maxStaleMs,
    onError: options.onError,
  });

  const verifyOpts = {
    algorithms,
    issuer: options.issuer,
    requiredClaims: options.requiredClaims,
    clockToleranceSec: options.clockToleranceSec,
  };

  let started = null;

  /** 同步驗證（快取 miss 時 fail-closed，背景補抓）。 */
  function verifySync(token, extra) {
    return verifyJwt(token, { ...verifyOpts, ...extra, getKey: cache.getKey });
  }

  /**
   * 非同步驗證：快取 miss 時**等**一次抓取。重啟後第一個請求就能成功。
   * 在無法保證開機預熱的環境（Next.js / serverless）請用這支。
   */
  function verify(token, extra) {
    return verifyJwtAsync(token, { ...verifyOpts, ...extra, getKey: cache.getKeyAsync });
  }

  /** 開機預熱：等第一次 JWKS 抓取完成。重複呼叫共用同一個 promise。 */
  function ready() {
    if (!started) started = cache.start();
    return started;
  }

  if (options.autoStart !== false) ready();

  return {
    verify,
    verifySync,
    bearer: bearerToken,
    ready,
    refresh: cache.refresh,
    whenIdle: cache.whenIdle,
    stats: cache.stats,
    stop: cache.stop,
    getKey: cache.getKey,
    getKeyAsync: cache.getKeyAsync,
    jwksUrl: url,
  };
}

/**
 * LetMeUse 專用預設（Jeff 生態系）。
 *
 * 跟泛用版的差別只有三件事，但都是實際踩過的坑：
 *   1. jwksPath 預設 `/api/jwks`（LetMeUse 不是標準的 .well-known 路徑）
 *   2. **appId 必填，缺了就 throw**。LetMeUse 用同一把 ES256 金鑰簽發所有
 *      app 的 token，所以 `app` claim 是唯一的租戶邊界。少了它不是「少一道
 *      檢查」，而是「任何 LetMeUse app 的任何使用者都能進來」。讓它在啟動時
 *      就炸，而不是上線後才靜默放行。
 *   3. 網址從 env 取（LETMEUSE_JWKS_URL → LETMEUSE_BASE_URL + /api/jwks），
 *      kit 內不寫死任何主機。
 */
function createLetMeUseVerifier(options = {}) {
  const appId = options.appId !== undefined ? options.appId : process.env.LETMEUSE_APP_ID;
  if (typeof appId !== "string" || !appId) {
    throw new Error(
      "jwks-verify-kit: createLetMeUseVerifier 需要 appId（LetMeUse 所有 app 共用同一把簽章金鑰，"
      + "app claim 是唯一的租戶邊界 —— 沒有它等於接受任何 app 的使用者）",
    );
  }
  const { appId: _ignored, ...rest } = options;
  return createJwksVerifier({
    ...rest,
    jwksUrl: options.jwksUrl || process.env.LETMEUSE_JWKS_URL || "",
    baseUrl: options.baseUrl || process.env.LETMEUSE_BASE_URL || "",
    jwksPath: options.jwksPath || "/api/jwks",
    algorithms: options.algorithms || ["ES256"],
    requiredClaims: { app: appId, ...(options.requiredClaims || {}) },
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
