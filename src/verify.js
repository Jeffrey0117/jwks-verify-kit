// 純函式的非對稱 JWT 驗證。沒有網路、沒有狀態、沒有 env —— 公鑰由 getKey 注入。
//
// 回傳 claims 或 null。**永不 throw**：驗證失敗不是例外狀況，而是日常。
// 讓它 throw 會逼每個呼叫端包 try/catch，而漏包的那個就會變成 500（洩漏堆疊），
// 或更糟 —— 被上層的 catch-all 吃掉變成放行。
//
// 拆成三段是為了讓同步與非同步共用同一套規則：decodeHeader（格式）→ 取金鑰
// （同步或 await）→ verifyWithKey（簽章＋claims）。規則只有一份，不會漂。
//
// 每一個拒絕點都會呼叫 `onReject({ reason, ... })`（如果宿主有給）。理由見下方
// `rejecter` 的註解：一個只會回 null 的驗證器在出事時是查不動的。

const crypto = require("node:crypto");
const { ALGORITHMS, DEFAULT_ALGS } = require("./algorithms");

// 🔒 嚴格 base64url 字集。`Buffer.from(x, "base64url")` 會**默默忽略**字母表外
// 的字元，所以同一顆 token 存在很多種等價寫法。這本身不是驗簽漏洞（被簽的是
// 原始字串），但只要有任何東西以 token 字串當 key —— 重放快取、idempotency
// key、撤銷黑名單、限流桶、log 比對 —— 就會被輕易繞過。
const B64URL = /^[A-Za-z0-9_-]+$/;

// payload / header 裡出現這些 own key 一律拒絕。IdP 沒有任何理由發這種 claim，
// 而宿主只要做過 `Object.assign(session, claims)` 就會把它們寫進原型鏈
// （`{...claims}` 安全，`Object.assign` 不安全 —— 後者走 Set，會觸發目標原型
// 上的 `__proto__` setter）。把 claims 物件做成 null-prototype **不能**解決這點，
// 因為那個 setter 住在「目標」的原型上，所以 key 本身必須消失。
const FORBIDDEN_KEYS = ["__proto__", "constructor", "prototype"];

// 唯一允許「token 的值是陣列時比對成員」的 claim。RFC 7519 只把 `aud` 定義成
// 可多值；把這個行為放寬到任意 claim 會連租戶邊界一起放寬（理由見下方註解）。
const MULTI_VALUED_CLAIM = "aud";

/**
 * 做一個「拒絕」函式：回報原因然後回 null。
 *
 * 為什麼需要它：一個只會回 null 的驗證器在出事時查不動。真實場景是「使用者說
 * 他登不進去」，而伺服器只知道 401 —— 到底是 token 過期、kid 還沒輪換進快取、
 * 還是 app claim 不符？這個 kit 的 README 把「fail-closed 沒有可觀測性」列成
 * 要解決的坑，但在 2026-11-08 之前只解到快取層（stats()），逐顆 token 的層級
 * 還是黑盒子 —— plottr 因此自己在每個拒絕點寫了 console.warn。
 *
 * `reason` 是穩定的識別字串（kebab-case，ASCII），可以直接 grep 或當 metric 的
 * label；不要拿去給使用者看。
 *
 * ⚠️ 兩條使用守則：
 *   1. **回呼丟錯不能影響驗證結果。** 包在 try/catch 裡，而且吞掉 —— 日誌壞掉
 *      不該變成認證通過或 500。
 *   2. **detail 裡的值大多是呼叫端送來的**（alg / kid / claim 的實際值）。寫進
 *      自己的 log 沒問題，但**不要原樣回給呼叫端**，那是反射式資訊外洩（我在
 *      selfize 的公開健檢端點把 lastMissKid 反射出去過）。
 */
function rejecter(options) {
  const cb = options && typeof options.onReject === "function" ? options.onReject : null;
  if (!cb) return () => null;
  return (reason, detail) => {
    try {
      cb(detail ? Object.assign({ reason }, detail) : { reason });
    } catch (e) {
      /* 日誌壞掉不該影響驗證結果 */
    }
    return null;
  };
}

/**
 * 解析一段 base64url JSON。
 *
 * 回傳的物件是 **null-prototype**：否則「缺少的 claim」會沿著原型鏈解析到
 * `Object.prototype` 上的同名屬性。真實後果是：行程裡任何一處 prototype
 * pollution（常見漏洞類別）＋一顆沒有 exp / 沒有 app 的合法簽章 token
 * ＝ 永不過期、任何租戶都通。
 */
// 遞迴掃描的上限。claims 是 IdP 發的小物件；設上限只是為了讓「惡意的深層巢狀
// JSON」不能把這個檢查變成 CPU 攻擊面。超過上限就**拒絕**（不是放行）。
const MAX_SCAN_DEPTH = 6;
const MAX_SCAN_NODES = 512;

/**
 * 整棵 claims 樹裡不准有 own `__proto__` / `constructor` / `prototype` key。
 *
 * ⚠️ 2026-11-08：原本只檢查**頂層**。security review 指出
 * `{"sub":"u","profile":{"__proto__":{"isAdmin":true}}}` 會過 —— 雖然那需要 IdP
 * 的私鑰才簽得出來，但宿主對巢狀物件做 `Object.assign(target, claims.profile)`
 * 是很自然的寫法，而那一下就污染 target 的原型。這個 kit 的立場是「claim 的形狀
 * 可疑就拒絕」，所以整棵都檢查。
 *
 * @returns {boolean} true = 乾淨
 */
function treeIsClean(value, depth = 0, counter = { n: 0 }) {
  if (value === null || typeof value !== "object") return true;
  counter.n += 1;
  if (depth > MAX_SCAN_DEPTH || counter.n > MAX_SCAN_NODES) return false;
  if (Array.isArray(value)) {
    for (const item of value) {
      if (!treeIsClean(item, depth + 1, counter)) return false;
    }
    return true;
  }
  for (const bad of FORBIDDEN_KEYS) {
    if (Object.prototype.hasOwnProperty.call(value, bad)) return false;
  }
  for (const key of Object.keys(value)) {
    if (!treeIsClean(value[key], depth + 1, counter)) return false;
  }
  return true;
}

function decodeJson(segment) {
  try {
    const parsed = JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    if (!treeIsClean(parsed)) return null;
    return Object.assign(Object.create(null), parsed);
  } catch {
    return null;
  }
}

/**
 * 解析 algorithms 選項。
 * 沒給 → 預設 ES256。給了但不是「非空字串陣列」→ null（呼叫端 fail-closed）。
 * 刻意不默默退回預設值：`algorithms: "ES384"`（忘了包陣列）會變成「所有真的
 * ES384 token 全被拒絕且零解釋」。
 */
function resolveAlgorithms(options) {
  if (options.algorithms === undefined || options.algorithms === null) return DEFAULT_ALGS;
  if (!Array.isArray(options.algorithms) || options.algorithms.length === 0) return null;
  if (!options.algorithms.every((a) => typeof a === "string" && a)) return null;
  return options.algorithms;
}

/**
 * 第一段：純格式與 header 檢查，完全不碰金鑰。
 * 通過回 { kid, spec, headerSeg, payloadSeg, sigSeg }，否則 null。
 */
function decodeHeader(token, options = {}) {
  const reject = rejecter(options);
  if (typeof token !== "string" || !token) return reject("token-not-string");
  const allowed = resolveAlgorithms(options);
  if (!allowed) return reject("algorithms-option-invalid");

  const parts = token.split(".");
  if (parts.length !== 3) return reject("not-three-segments", { segments: parts.length });
  const [headerSeg, payloadSeg, sigSeg] = parts;
  if (!B64URL.test(headerSeg) || !B64URL.test(payloadSeg) || !B64URL.test(sigSeg)) {
    return reject("segment-not-base64url");
  }

  const header = decodeJson(headerSeg);
  if (!header) return reject("header-not-json");
  // alg 用白名單：擋掉 alg:none、HS256（對稱 → secret 外洩即可自簽）與演算法混淆
  if (typeof header.alg !== "string" || !allowed.includes(header.alg)) {
    return reject("alg-not-allowed", { alg: header.alg, allowed });
  }
  const spec = ALGORITHMS[header.alg];
  if (!spec) return reject("alg-unsupported", { alg: header.alg }); // allowed 裡寫了本 kit 不支援的 alg → 不猜，拒絕
  // kid 必填：JWKS 在輪換期間一定有多把金鑰，沒有 kid 就只能猜，而「猜第一把」
  // 正是常見的輪換期漏洞 —— 它會讓被撤銷的金鑰繼續生效。
  if (typeof header.kid !== "string" || !header.kid) return reject("kid-missing");
  // RFC 7515 §4.1.11：crit 列的擴充是「必須理解否則拒收」。本 kit 不支援任何
  // 擴充，所以只要 crit 存在就拒絕，而不是視而不見。
  if (header.crit !== undefined) return reject("crit-unsupported");
  // 簽章長度在解碼前就能判斷，順手擋掉 DER 編碼（JWS 規定 raw r||s）與垃圾
  if (sigSeg.length !== spec.b64urlChars) {
    return reject("sig-length", { alg: header.alg, expected: spec.b64urlChars, actual: sigSeg.length });
  }

  return { kid: header.kid, spec, headerSeg, payloadSeg, sigSeg };
}

/** 第三段：有了金鑰之後驗簽章並檢查 claims。 */
function verifyWithKey(parsed, publicKey, options = {}) {
  const reject = rejecter(options);
  if (!parsed) return null; // decodeHeader 已經回報過原因了
  if (!publicKey) return reject("key-not-found", { kid: parsed.kid });
  const { spec, headerSeg, payloadSeg, sigSeg } = parsed;

  // 金鑰的曲線必須跟 header 宣告的 alg 相符。node 的 ieee-p1363 路徑實測已經
  // 會把簽章長度綁到金鑰的 field size（所以跨曲線混淆進不來），但那是 OpenSSL
  // 的行為；明寫一行讓保證住在這個 kit 裡，而不是別人的實作細節裡。
  try {
    const curve = publicKey.asymmetricKeyDetails && publicKey.asymmetricKeyDetails.namedCurve;
    if (curve && spec.nodeCurves && !spec.nodeCurves.includes(curve)) {
      return reject("key-curve-mismatch", { kid: parsed.kid, curve, expected: spec.nodeCurves });
    }
  } catch (e) {
    return reject("key-inspect-failed", { kid: parsed.kid });
  }

  const signature = Buffer.from(sigSeg, "base64url");
  // 縱深防禦：在嚴格字集 + 精確字數檢查之後這條其實**不可達**（86/128/176 個
  // base64url 字元必定解出 64/96/132 bytes）。留著是因為它便宜，而且萬一未來
  // 有人放寬上面兩條，這裡還擋得住。別花時間想替它寫測試。
  if (signature.length !== spec.sigBytes) return reject("sig-bytes");
  // 🔒 正規化檢查：86 個 base64url 字元帶 516 bits，而 ES256 簽章只有 512 bits
  // → 有 4 個自由位元，於是同一個簽章有 16 種等價寫法（實測另外 15 種全都驗得
  // 過）。字集檢查擋不到這個。只要宿主有任何東西以 token 字串當 key（撤銷黑
  // 名單、重放/idempotency 快取、限流桶、log 去重），持有一顆有效 token 的人
  // 就能繞過。⚠️ 這條只消滅「編碼層」的等價寫法：ECDSA 的 (r, n−s) 也驗得過
  // （node 不強制 low-s），那個無法靠編碼正規化解決 —— 所以 SKILL.md 明寫
  // 「永遠不要用 token 字串當 key」。
  if (signature.toString("base64url") !== sigSeg) return reject("sig-not-canonical");

  let ok = false;
  try {
    ok = crypto.verify(
      spec.digest,
      Buffer.from(`${headerSeg}.${payloadSeg}`),
      { key: publicKey, dsaEncoding: "ieee-p1363" },
      signature,
    );
  } catch (e) {
    return reject("sig-verify-threw", { kid: parsed.kid }); // 金鑰型別與 alg 不搭之類 → 拒絕，不要炸
  }
  if (!ok) return reject("sig-invalid", { kid: parsed.kid });

  // 簽章過了才解析 payload（先解析再驗簽 = 拿未驗證資料做決策）
  const claims = decodeJson(payloadSeg);
  if (!claims) return reject("payload-not-json");

  const skew = typeof options.clockToleranceSec === "number" && options.clockToleranceSec > 0
    ? options.clockToleranceSec
    : 0;
  const now = typeof options.now === "number" ? options.now : Math.floor(Date.now() / 1000);

  // 🔒 exp 必填且必須是數字。沒有 exp 的 token 等於永不過期；字串型 exp 會讓
  // `exp <= now` 這種比較靜默失效 → 無限期有效。短 exp 往往是這類設計唯一的
  // 撤銷機制，不能讓它消失。
  if (typeof claims.exp !== "number" || !Number.isFinite(claims.exp)) {
    return reject("exp-missing-or-not-number", { expType: typeof claims.exp });
  }
  if (claims.exp + skew <= now) return reject("expired", { exp: claims.exp, now });
  // nbf 若存在就要尊重；非數字的 nbf 視為可疑，不是單純忽略
  if (claims.nbf !== undefined) {
    if (typeof claims.nbf !== "number" || !Number.isFinite(claims.nbf)) {
      return reject("nbf-not-number", { nbfType: typeof claims.nbf });
    }
    if (claims.nbf - skew > now) return reject("not-yet-valid", { nbf: claims.nbf, now });
  }

  if (options.issuer !== undefined) {
    if (!options.issuer) return reject("issuer-option-empty"); // 設了但是空值 → fail-closed
    if (claims.iss !== options.issuer) return reject("issuer-mismatch", { iss: claims.iss });
  }

  // 🔒 requiredClaims：租戶／受眾邊界。
  // 預設**完全相等**；只有 RFC 7519 真正定義成可多值的 `aud` 例外（見下）。
  // 為什麼「設定值是空的就拒絕」而不是「跳過檢查」：IdP 往往用**同一把金鑰**
  // 簽發所有 app 的 token（LetMeUse 就是），此時 `app` claim 是唯一的租戶邊界。
  // 寫成 `if (expected && claims[c] !== expected)` 的話，自己忘了設 APP_ID 就
  // 變成「接受任何 app 的任何使用者」—— 這個 fail-open 在 Jeff 生態系實際發生
  // 過三次。設定不全要壞得大聲。
  //
  // 型別也要擋：`required && typeof required === "object"` 這種寫法會讓
  // `requiredClaims: '{"app":"x"}'`（忘了 JSON.parse 的字串）整個檢查消失，
  // 而且 45 個測試照樣全綠。設錯型別 → fail-closed。
  if (options.requiredClaims !== undefined && options.requiredClaims !== null) {
    const required = options.requiredClaims;
    if (typeof required !== "object" || Array.isArray(required)) {
      return reject("required-claims-option-not-object", { got: typeof required });
    }
    for (const claim of Object.keys(required)) {
      const expected = required[claim];
      if (expected === undefined || expected === null || expected === "") {
        return reject("required-claim-option-empty", { claim });
      }
      const actual = claims[claim];
      // `aud` 依 RFC 7519 §4.1.3 允許是字串或字串陣列（Auth0 / Keycloak /
      // Cognito 都會發陣列），嚴格 `!==` 會把那些真 token 全擋掉 → 只有這個
      // claim 做成員比對。
      //
      // 🔒 **刻意不讓它適用於其他 claim**：租戶 claim（LetMeUse 的 `app`）若
      // 也接受「集合包含」，那麼一顆 `app: ["app_mine","app_other"]` 的 token
      // 就能同時通過兩個租戶的驗證 —— 而它是簽名有效的真 token，沒有任何線索。
      // 今天 LetMeUse 不發陣列 app，但哪天多了「多 app token」這種功能，所有
      // 消費端會同時靜默變寬。租戶邊界要嚴格相等。
      if (claim === MULTI_VALUED_CLAIM && Array.isArray(actual)) {
        if (!actual.every((v) => typeof v === "string") || !actual.includes(expected)) {
          return reject("required-claim-mismatch", { claim, actual });
        }
      } else if (actual !== expected) {
        return reject("required-claim-mismatch", { claim, actual });
      }
    }
  }

  // 🔒 sub 必須是非空字串（預設開啟，requireSubject: false 可關）。
  // access token 的 sub 就是身分，而宿主幾乎都拿它當 DB 的 key —— 物件型 sub
  // 會讓 better-sqlite3 丟錯變 500，數字型會悄悄跟別人的 id 撞號。
  // 這條原本只寫在 SKILL.md 的稽核清單裡而程式碼沒做，等於文件在騙人。
  if (options.requireSubject !== false) {
    if (typeof claims.sub !== "string" || !claims.sub) {
      return reject("sub-not-string", { subType: typeof claims.sub });
    }
  }

  // 🔒 allowedClaims：多租戶版的邊界（claim 必須落在允許清單裡）。
  // selfize 這種「一個儲存服務同時服務好幾個 app」的消費端不能綁單一值，但
  // 「清單是空的」必須跟 requiredClaims 一樣 fail-closed —— 否則就回到
  // 「生態系任何 app 的任何使用者都進得來」。
  if (options.allowedClaims !== undefined && options.allowedClaims !== null) {
    const allowed = options.allowedClaims;
    if (typeof allowed !== "object" || Array.isArray(allowed)) {
      return reject("allowed-claims-option-not-object", { got: typeof allowed });
    }
    for (const claim of Object.keys(allowed)) {
      const list = allowed[claim];
      if (!Array.isArray(list) || list.length === 0) {
        return reject("allowed-claim-list-empty", { claim });
      }
      // 注意方向：這裡是「token 的單一值必須落在允許清單裡」。token 的 claim
      // 本身是陣列時一律 fail-closed（陣列不會等於清單裡的任何字串）—— 跟
      // requiredClaims 的 aud 成員比對剛好相反，這是刻意的：allowedClaims 是
      // 租戶邊界用的，寧可拒絕也不要去猜「陣列裡有一個命中算不算通過」。
      if (!list.includes(claims[claim])) {
        return reject("allowed-claim-not-in-list", { claim, actual: claims[claim] });
      }
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
 *   allowedClaims?: Record<string, unknown[]>,
 *   clockToleranceSec?: number, now?: number,
 *   onReject?: (info: { reason: string }) => void,
 * }} options
 * @returns {Record<string, unknown>|null}
 */
function verifyJwt(token, options) {
  const opts = options || {};
  const reject = rejecter(opts);
  if (typeof opts.getKey !== "function") return reject("getkey-not-function"); // 設定不全 → fail-closed
  const parsed = decodeHeader(token, opts);
  if (!parsed) return null;
  let key = null;
  try {
    key = opts.getKey(parsed.kid);
  } catch (e) {
    return reject("getkey-threw", { kid: parsed.kid });
  }
  return verifyWithKey(parsed, key, opts);
}

/** 同上，但 getKey 可以回 promise（快取 miss 時等一次抓取）。 */
async function verifyJwtAsync(token, options) {
  const opts = options || {};
  const reject = rejecter(opts);
  if (typeof opts.getKey !== "function") return reject("getkey-not-function");
  const parsed = decodeHeader(token, opts);
  if (!parsed) return null;
  let key = null;
  try {
    key = await opts.getKey(parsed.kid);
  } catch (e) {
    return reject("getkey-threw", { kid: parsed.kid }); // 取金鑰失敗 → 拒絕，不要讓例外冒到路由層
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
