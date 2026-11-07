---
name: jwks-verify-kit
description: Use when a service needs to VERIFY access tokens issued by an external identity provider (LetMeUse, Auth0, Clerk, Keycloak…) — "接 LetMeUse 登入"、"驗 JWT"、"加 JWKS"、"把 HS256 換成 ES256"、route handler 要認使用者身分。Also use when auditing an existing verifier for fail-opens. NOT for issuing your own sessions (that is auth-kit).
---

# jwks-verify-kit — 打法

**當消費端，驗別人家 IdP 發的非對稱 JWT。** 零依賴、fail-closed、公鑰走 JWKS。

## 何時觸發

- 任何「這支 API 要知道呼叫者是誰」而身分來自外部 IdP 的時候
- 看到 `HS256`、`createHmac` 出現在**驗證**路徑上 → 停，換成這個 kit
- 看到自己手寫的 `createPublicKey({ format: 'jwk' })` + `crypto.verify` → 那是這個 kit 的範圍，別重造
- 稽核現有驗證器（下面「稽核清單」直接拿去對）

**不適用**：自己發 session / 存密碼 → `auth-kit`。機器對機器 → 見下面「機器不要拿 JWT」。

## 接線（照抄能跑）

```bash
npm i github:Jeffrey0117/jwks-verify-kit
```

```js
const { createLetMeUseVerifier } = require('jwks-verify-kit');

const auth = createLetMeUseVerifier({
  appId: process.env.LETMEUSE_APP_ID,
  baseUrl: process.env.LETMEUSE_BASE_URL,
  onError: (e) => console.warn('[jwks]', e.message),
});

// ① 開機預熱（同步驗證的前提）。回傳 stats()，別只看它 resolve 了。
const s = await auth.ready();
if (!s.keys) console.error('[boot] JWKS 沒金鑰，所有登入都會失敗:', s.lastError);

// ② 路由
const claims = auth.verifySync(auth.bearer(req.headers.authorization));
if (!claims) return res.writeHead(401).end();

// ③ 健檢要露出 JWKS 狀態，回 200 不要回 503
json(res, { ok: true, jwks: auth.stats() });
```

env 只要兩個：`LETMEUSE_APP_ID`、`LETMEUSE_BASE_URL`（或 `LETMEUSE_JWKS_URL`）。

**`LETMEUSE_APP_SECRET` 要從該機器刪掉** —— 驗 ES256 根本不需要它，留著只是多一個外洩點。走 cloudpipe env API，`vars` 的值給 `null` 即刪鍵；那個 PUT 撞到部署佇列會回 504 但**有可能延後才生效**，所以別只看 HTTP 狀態，回頭讀 `.env` 確認。

**Next.js / serverless** 用 `await auth.verifyAsync(token)`（instrumentation 和 route handler 可能是不同 module 實例，預熱到的是另一份快取）。注意它刻意不叫 `verify` —— 忘了 await 的話 `if (!claims)` 會拿到 truthy 的 Promise 而放行。

**多租戶**（一個服務服務多個 app，像 selfize）用 `allowedClaims: { app: [...] }`，空陣列 = 拒絕全部。

## 稽核清單（改既有驗證器時逐條對）

1. `alg` 是**白名單**嗎？（黑名單會漏 `alg:none`）
2. `kid` 必填嗎？不符時有沒有「退回第一把金鑰」（`|| keys[0]`）？那會讓撤銷的金鑰繼續生效
3. `exp` 是**必填且必須是數字**嗎？（`if (typeof exp === 'number' && exp <= now)` = 沒 exp 等於永不過期）
4. 租戶 claim（LetMeUse 的 `app`）有強制嗎？自己沒設 appId 時是**拒絕**還是放行？
5. `sub` 有檢查型別嗎？（非字串的 sub 流進 DB 當 key 會變 500 或撞號。本 kit 的 `requireSubject` 預設開啟）
6. JWKS 抓取有**逾時**嗎？（node 的 fetch 沒有預設值）
7. 格式正確的**空 JWKS** 會覆蓋快取嗎？（不覆蓋 = 撤銷不生效）
8. JWKS 走 https 嗎？（它是信任根，明文 = 同網段任何人都能換掉公鑰）
9. 開機有預熱嗎？（沒有 = 重啟後第一個請求必 401）
10. fail-closed 的狀態看得見嗎？（`stats()` 上健檢；`onError` 不要是 noop）
11. 數字設定有驗證嗎？（`Number(process.env.X)` 沒設時是 `NaN`，會靜默關掉保護）

## 模式與文案

- **401 vs 403 分清楚**：沒有有效憑證 = 401；驗過了但不是這個人 = 403。拿不到身分時回 403 是在說「你不是對的人」，但其實我們根本不知道你是誰。
- **⛔ 永遠不要用 token 字串當 key。** 撤銷黑名單、重放／idempotency 快取、限流桶、log 去重 —— 全部改用 `jti`，沒有 `jti` 就用 `(sub, iat)`。理由：ES256 簽章的 86 個 base64url 字元帶 516 bits 而簽章只有 512 bits，所以同一個簽章有 16 種等價寫法（本 kit 已經把非正規化的 15 種擋掉了）；但 ECDSA 的 `(r, n−s)` 也驗得過（node 不強制 low-s），**那個無法靠編碼正規化解決**。唯一可靠的唯一性來自 IdP 自己發的 id。
- **機器不要拿 JWT**。給 MCP 工具 / gateway 用的憑證要是**不透明隨機字串 + constant-time 比對**，不要自簽一顆長期的「使用者」JWT。後者錯兩次：逼驗證端支援對稱簽章（= 保留那個洞），又把機器假扮成人。areyoubot 的 `AREYOUBOT_SERVICE_TOKEN` 曾是一把一年期 HS256 JWT（`sub=usr_mcp_admin`），已改掉。
- **前端那側另有鐵則**：access token 只活 4h、refresh token 30 天，`letmeuse.getToken()` 回的是生的 localStorage 值（可能已過期）。頁面一載入就打 API 的前端要等 `letmeuse.ready`，且 init 期間的 401 不准跳「登入過期」。症狀指紋＝回訪時誤跳過期、兩秒後又登回來。
- **登入中繼頁的 XSS = 帳號接管**。那個 origin 的 localStorage 存著 refresh token，一個 XSS 就繞過整套簽章驗證。`JSON.stringify` **不會**轉義 `</script>`，把參數內嵌進 `<script>` 時要額外把 `<` `>` `&` U+2028/9 轉成 `\uXXXX`，參數本身也要收字集。

## 地雷

- **只收 HS256 跟兩種都收，中招長相差很多**：只收 HS256 → 真 token 全被擋、功能整個壞掉（fail-closed，不是洞），症狀是「部署成功、健檢綠燈，但沒人能登入，而統計是 0 看起來像還沒人用」。兩種都收（「過渡期」）→ **洞還開著**。
- **簽發端可能無聲退回 HS256**：LetMeUse 的 `signAccessToken` 只在 `LETMEUSE_SIGN_ALG=ES256` 且私鑰載得起來時簽 ES256，否則退回 HS256。哪次部署把 env 弄掉，全生態所有接入方會同時「全部 401 且零線索」—— 這就是為什麼 `stats()` 一定要上健檢。
- **LetMeUse 的 refresh token 走 HS256（用 app secret 簽）**，跟 access token 不同金鑰、也不經這條驗證路徑（redeem 時查儲存比對）。所以那把 ES256 金鑰只簽 access token 一種東西 —— 換 IdP 時要重新確認這點，否則「用同一把金鑰簽的 30 天 refresh token」會被當成 access token 收下。
- **LetMeUse 不帶 `typ` header**（`setProtectedHeader({ alg, kid })`），所以不要硬要求 `typ: "JWT"`，會把所有真 token 擋掉。
- **逾時計時器不要 `unref()`**：unref 的計時器在「沒有其他事情撐著 event loop」時不會觸發，卡死的 fetch 就永遠等不到逾時（寫測試時會直接現形）。
- **ESM 的 export 不能 monkey-patch**：想在測試裡換掉 `getJwksPublicKey` 會拿到 `TypeError: Cannot assign to read only property`。所以這個 kit 一律用注入（`getKey` / `fetchImpl`），測試不用碰 module 內部。
- **驗「新碼是否真的上線」要用有鑑別力的測試**：「真 token 通、別的 app 擋」舊碼往往也會過，等於沒驗到。要挑只有新碼才會變的行為，例如**沒有 `exp` 的 token**（舊碼放行、新碼擋）。
- **ES512 的曲線是 P-521 不是 P-512**（簽章 132 bytes、176 個 base64url 字元）。抄表格時容易寫錯，kit 有測試鎖住。
- **`.env` 的 CRLF 尾巴**會讓 `LETMEUSE_APP_ID` 比不中 → 每顆真 token 都被拒絕，而 `stats()` 一片健康（`keys:1, lastError:null`）。kit 的 LetMeUse 預設會 trim，但自己讀 env 的地方要注意。
