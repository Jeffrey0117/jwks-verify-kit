// 純函式的非對稱 JWT 驗證。沒有網路、沒有狀態、沒有 env —— 公鑰由 getKey 注入。
//
// 回傳 claims 或 null。**永不 throw**：驗證失敗不是例外狀況，而是日常。
// 讓它 throw 會逼每個呼叫端包 try/catch，而漏包的那個就會變成 500（洩漏堆疊），
// 或更糟 —— 被上層的 catch-all 吃掉變成放行。
//
// 拆成三段是為了讓同步與非同步共用同一套規則：decodeHeader（格式）→ 取金鑰
// （同步或 await）→ verifyWithKey（簽章＋claims）。規則只有一份，不會漂。

const crypto = require("node:crypto");
const { ALGORITHMS } = require("./algorithms");

// 🔒 嚴格 base64url 字集。`Buffer.from(x, "base64url")` 會**默默忽略**字母表外
// 的字元，所以同一顆 token 存在很多種等價寫法（實測：簽章段最後一字有 15 種
// 寫法，中間插 `!` 或換行也照樣過）。這本身不是驗簽漏洞（被簽的是原始字串），
// 但只要有任何東西以 token 字串當 key —— 重放快取、idempotency key、撤銷黑
// 名單、限流桶、log 比對 —— 就會被輕易繞過。在這裡釘死比日後踩到便宜。
const B64URL = /^[A-Za-z0-9_-]+$/;

function decodeJson(segment) {
  try {
    const parsed = JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
  } catch (e) {
    return null;
  }
}

function allowedAlgsOf(options) {
  return Array.isArray(options.algorithms) && options.algorithms.length > 0
    ? options.algorithms
    : ["ES256"];
}

/**
 * 第一段：純格式與 header 檢查，完全不碰金鑰。
 * 通過回 { kid, spec, headerSeg, payloadSeg, sigSeg }，否則 null。
 */
function decodeHeader(token, options = {}) {
  if (typeof token !== "string" || !token) return null;
  const allowed = allowedAlgsOf(options);

  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [headerSeg, payloadSeg, sigSeg] = parts;
  if (!B64URL.test(headerSeg) || !B64URL.test(payloadSeg) || !B64URL.test(sigSeg)) return null;

  const header = decodeJson(headerSeg);
  if (!header) return null;
  // alg 用白名單：擋掉 alg:none、HS256（對稱 → secret 外洩即可自簽）與演算法混淆
  if (typeof header.alg !== "string" || !allowed.includes(header.alg)) return null;
  const spec = ALGORITHMS[header.alg];
  if (!spec) return null; // allowed 裡寫了本 kit 不支援的 alg → 不猜，拒絕
  // kid 必填：JWKS 在輪換期間一定有多把金鑰，沒有 kid 就只能猜，而「猜第一把」
  // 正是常見的輪換期漏洞 —— 它會讓被撤銷的金鑰繼續生效，或拿新金鑰硬驗舊簽章。
  if (typeof header.kid !== "string" || !header.kid) return null;
  // 簽章長度在解碼前就能判斷，順手擋掉 DER 編碼（JWS 規定 raw r||s）與垃圾
  if (sigSeg.length !== spec.b64urlChars) return null;

  return { kid: header.kid, spec, headerSeg, payloadSeg, sigSeg };
}

/** 第三段：有了金鑰之後驗簽章並檢查 claims。 */
function verifyWithKey(parsed, publicKey, options = {}) {
  if (!parsed || !publicKey) return null;
  const { spec, headerSeg, payloadSeg, sigSeg } = parsed;

  const signature = Buffer.from(sigSeg, "base64url");
  if (signature.length !== spec.sigBytes) return null;

  let ok = false;
  try {
    ok = crypto.verify(
      spec.digest,
      Buffer.from(`${headerSeg}.${payloadSeg}`),
      { key: publicKey, dsaEncoding: "ieee-p1363" },
      signature,
    );
  } catch (e) {
    return null; // 金鑰型別與 alg 不搭之類 → 拒絕，不要炸
  }
  if (!ok) return null;

  // 簽章過了才解析 payload（先解析再驗簽 = 拿未驗證資料做決策）
  const claims = decodeJson(payloadSeg);
  if (!claims) return null;

  const skew = typeof options.clockToleranceSec === "number" && options.clockToleranceSec > 0
    ? options.clockToleranceSec
    : 0;
  const now = typeof options.now === "number" ? options.now : Math.floor(Date.now() / 1000);

  // 🔒 exp 必填且必須是數字。沒有 exp 的 token 等於永不過期；字串型 exp 會讓
  // `exp <= now` 這種比較靜默失效 → 無限期有效。短 exp 往往是這類設計唯一的
  // 撤銷機制，不能讓它消失。
  if (typeof claims.exp !== "number" || !Number.isFinite(claims.exp)) return null;
  if (claims.exp + skew <= now) return null;
  // nbf 若存在就要尊重；非數字的 nbf 視為可疑，不是單純忽略
  if (claims.nbf !== undefined) {
    if (typeof claims.nbf !== "number" || !Number.isFinite(claims.nbf)) return null;
    if (claims.nbf - skew > now) return null;
  }

  if (options.issuer !== undefined) {
    if (!options.issuer) return null; // 設了但是空值 → fail-closed
    if (claims.iss !== options.issuer) return null;
  }

  // 🔒 requiredClaims：租戶／受眾邊界。
  // 為什麼「設定值是空的就拒絕」而不是「跳過檢查」：IdP 往往用**同一把金鑰**
  // 簽發所有 app 的 token（LetMeUse 就是），此時 `app` claim 是唯一的租戶邊界。
  // 寫成 `if (expected && claims[c] !== expected)` 的話，自己忘了設 APP_ID 就
  // 變成「接受任何 app 的任何使用者」—— 這個 fail-open 在 Jeff 生態系實際發生
  // 過三次。設定不全要壞得大聲。
  const required = options.requiredClaims;
  if (required && typeof required === "object") {
    for (const claim of Object.keys(required)) {
      const expected = required[claim];
      if (expected === undefined || expected === null || expected === "") return null;
      if (claims[claim] !== expected) return null;
    }
  }

  return claims;
}

/**
 * 同步驗證。getKey 回 null（不認識的 kid / 快取還沒暖）就拒絕 —— fail-closed。
 *
 * @param {string} token
 * @param {{
 *   getKey: (kid: string) => import("node:crypto").KeyObject|null,
 *   algorithms?: string[], issuer?: string,
 *   requiredClaims?: Record<string, unknown>,
 *   clockToleranceSec?: number, now?: number,
 * }} options
 * @returns {Record<string, unknown>|null}
 */
function verifyJwt(token, options) {
  const opts = options || {};
  if (typeof opts.getKey !== "function") return null; // 設定不全 → fail-closed
  const parsed = decodeHeader(token, opts);
  if (!parsed) return null;
  return verifyWithKey(parsed, opts.getKey(parsed.kid), opts);
}

/** 同上，但 getKey 可以回 promise（快取 miss 時等一次抓取）。 */
async function verifyJwtAsync(token, options) {
  const opts = options || {};
  if (typeof opts.getKey !== "function") return null;
  const parsed = decodeHeader(token, opts);
  if (!parsed) return null;
  let key = null;
  try {
    key = await opts.getKey(parsed.kid);
  } catch (e) {
    return null; // 取金鑰失敗 → 拒絕，不要讓例外冒到路由層
  }
  return verifyWithKey(parsed, key, opts);
}

/**
 * 從 Authorization header 取 Bearer token。
 * scheme 依 RFC 6750 不分大小寫（`bearer xxx` 合法，擋掉它只是製造災難）。
 */
function bearerToken(authorization) {
  if (typeof authorization !== "string") return null;
  const match = /^Bearer[ \t]+(.+)$/i.exec(authorization.trim());
  if (!match) return null;
  const token = match[1].trim();
  return token || null;
}

module.exports = { verifyJwt, verifyJwtAsync, decodeHeader, verifyWithKey, bearerToken };
