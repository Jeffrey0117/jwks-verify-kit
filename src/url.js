// JWKS 網址的解析與**安全檢查**。
//
// 這條規則 2026-11-08 之前只住在 `index.js` 的 `createJwksVerifier` 路徑裡，而
// `createJwksCache`（低階積木）完全不檢查網址。結果是：生態系九個消費端為了「自己
// 管快取」全都走低階版 → 全都繞過了 https 強制。
//
// 那不是理論問題：`LETMEUSE_JWKS_URL=http://letmeuse.isnowfriend.com/api/jwks`
// 這種一個字的 env 錯誤會讓**信任根變成明文** —— 同網段任何人回自己的 JWKS，就能
// 替任何使用者簽 token，而且沒有任何錯誤訊息。所以規則必須住在最底層，不是住在
// 「比較高階的那條路徑」。
"use strict";

const LOCALHOST = ["localhost", "127.0.0.1", "[::1]", "::1"];

/**
 * 檢查並正規化 JWKS 網址。無效或明文（localhost 除外）→ throw。
 *
 * 刻意 throw 而不是回 null：設定錯誤要在啟動時大聲壞掉，不要變成「服務回 200、
 * 健檢全綠、但沒有人登入得進來」那種查不到的故障。
 */
function assertSafeJwksUrl(raw, options = {}) {
  if (typeof raw !== "string" || !raw) {
    throw new Error("jwks-verify-kit: JWKS 網址必填（收到空值）。沒有網址的驗證器會永遠拒絕每一顆 token，而服務照樣回 200 —— 那種故障最難查。");
  }
  let parsed;
  try {
    parsed = new URL(raw);
  } catch (e) {
    throw new Error(`jwks-verify-kit: JWKS 網址無效：${JSON.stringify(raw)}`);
  }
  const localhost = LOCALHOST.includes(parsed.hostname);
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

module.exports = { assertSafeJwksUrl, LOCALHOST };
