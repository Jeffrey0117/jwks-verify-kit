# jwks-verify-kit

**當消費端，驗別人家 IdP 發的非對稱 JWT。** 公鑰走 JWKS，零依賴（只用 node 內建 `crypto`），fail-closed。

這個 kit **不發 token**。要自己發 session 請用 [auth-kit](https://github.com/Jeffrey0117/auth-kit)。

## 為什麼需要它

不是為了少寫幾行，是為了不要再踩同一批坑。

對稱簽章（HS256）的致命問題是**驗證方必須握著簽發金鑰**。app secret 一外洩，任何人都能自簽一顆 `sub` / `role` 隨便填的 token 冒充任何人，包含管理員。改成非對稱（ES256）之後驗證方只需要公鑰——**那台機器可以完全不存任何 secret**，就算 secret 早就洩了，偽造的 token 一樣進不來。

而「驗 ES256 + 抓 JWKS」這件事看起來簡單，實際上有一整排會**靜默 fail-open** 的角落：

| 坑 | 不處理的後果 |
|---|---|
| `alg` 用黑名單而非白名單 | `alg:none`、HS256 混淆 |
| `kid` 可省略、不符就拿第一把金鑰 | 被撤銷的金鑰繼續生效 |
| `exp` 只在「是數字時」才比對 | 沒有 exp 的 token = 永不過期 |
| 租戶 claim 寫成 `if (expected && ...)` | 自己忘了設 APP_ID → 接受任何 app 的任何使用者 |
| 租戶 claim 的設定值型別沒檢查 | 忘了 `JSON.parse` 的字串 → **整個檢查消失**，而測試照樣全綠 |
| 空的 JWKS 不覆蓋舊快取 | 緊急撤銷金鑰永遠不生效 |
| node 的 `fetch` 沒有預設逾時 | 對方不回應 → 快取永久凍結、全部 401 且零診斷 |
| 設定值是 `NaN`（`Number(process.env.X)` 而 env 沒設） | 靜默關掉對應的保護 |
| JWKS 走 `http://` | 同網段任何人換掉公鑰 = 完整認證繞過（這條住在**最底層** `createJwksCache`：規則只放在高階版的話，自己管快取的消費端就全部繞過了） |
| 缺少的 claim 從 `Object.prototype` 解析到值 | prototype pollution ＋ 無 exp token = 永久通行證 |
| payload 帶 own `__proto__` key | 宿主 `Object.assign(session, claims)` → 原型污染 |
| 簽章段的非正規化寫法 | 同一顆 token 有 16 種寫法 → 撤銷黑名單／重放快取失效 |
| 未知 kid 的冷卻跟定時刷新共用 | 金鑰輪換跟不上 |
| 同步快取沒預熱 | 重啟後第一個請求必 401 |
| fail-closed 沒有可觀測性 | IdP 掛掉時查三小時查不到；逐顆 token 只有 401，分不出是過期、kid 還沒輪換進快取、還是租戶 claim 不符 |

每個專案自己寫一份 = 每個專案各自踩一半。這個 kit 就是那一份，而且每一條都有測試（`node --test`，**80 個**；六個 fail-open 另外用「還原修復確認變紅」驗證過）。

## 安裝

```bash
npm i github:Jeffrey0117/jwks-verify-kit
```

CommonJS 與 ESM 都能用（`require` 與具名 `import` 都實測過），**自帶 TypeScript 宣告**（`index.d.ts`，不必裝 `@types`）。那份宣告不只是補型別，它會在編譯期擋掉兩個最貴的用錯法：

```ts
const claims = auth.verifyAsync(token)   // 忘了 await
if (!claims) return 401                  // Promise 永遠 truthy → 全部放行
//  ^ TS 在 claims.sub 那行就會報錯

const c = auth.verifySync(token)
return c.sub                             // ^ 報錯：c 可能是 null
```

`test/types/must-fail.ts` 用 `@ts-expect-error` 把這些寫法釘成「必須報錯」，所以型別沒鬆掉這件事本身也有測試。

## 為什麼 401 要有理由

驗證失敗回 `null` 很乾淨，但出事的時候查不動：使用者說「我登不進去」，而伺服器
只知道 401 —— 到底是 token 過期、kid 還沒輪換進快取、還是 `app` claim 不符？

```js
const auth = createLetMeUseVerifier({
  appId: process.env.LETMEUSE_APP_ID,
  baseUrl: process.env.LETMEUSE_BASE_URL,
  onReject: (info) => console.warn(`[auth] 401 ${info.reason}`, info),
});
```

`reason` 是穩定的 kebab-case 字串，可以直接 grep 或當 metric 的 label：
`expired`、`key-not-found`、`required-claim-mismatch`、`sig-invalid`、
`exp-missing-or-not-number`、`alg-not-allowed`、`kid-missing`、`not-yet-valid`、
`sub-not-string`、`allowed-claim-not-in-list`、`getkey-not-function`…
（完整清單有測試釘住：改名字會讓依賴它做 alert 的宿主靜默失效。）

兩條守則：
- **回呼丟錯會被吞掉。** 日誌壞掉不該變成認證通過，也不該變成 500。
- **`info` 裡的值多半是呼叫端送來的**（`alg` / `kid` / claim 的實際值）。寫進
  自己的 log 沒問題，**不要原樣回給呼叫端** —— 那是反射式資訊外洩。

## 用法

### LetMeUse（Jeff 生態系）

```js
const { createLetMeUseVerifier } = require('jwks-verify-kit');

const auth = createLetMeUseVerifier({
  appId: process.env.LETMEUSE_APP_ID,          // 必填，缺了直接 throw（見下）
  baseUrl: process.env.LETMEUSE_BASE_URL,      // 或 jwksUrl 直接給完整網址
  onError: (e) => console.warn('[jwks]', e.message),
});

await auth.ready();                             // 開機預熱，很重要

// 路由裡
const claims = auth.verifySync(auth.bearer(req.headers.authorization));
if (!claims) return res.writeHead(401).end('unauthorized');
// claims = { sub, app, email, name, role, permissions, emailVerified, exp, iss }
```

`appId` 必填而且**缺了就 throw**，不是龜毛：LetMeUse 用**同一把 ES256 金鑰**簽發所有 app 的 token，所以 `app` claim 是唯一的租戶邊界。少了它不是「少一道檢查」，而是「任何 LetMeUse app 的任何使用者都能進來」。網址缺了也 throw——沒有網址的驗證器會永遠拒絕每一顆 token，而服務照樣回 200、健檢全綠，那種故障最難查。

### 任何其他 IdP

```js
const { createJwksVerifier } = require('jwks-verify-kit');

const auth = createJwksVerifier({
  jwksUrl: 'https://idp.example.com/.well-known/jwks.json',
  issuer: 'https://idp.example.com',      // 給了就比對 iss
  requiredClaims: { aud: 'my-api' },      // token 的 aud 是陣列時比對成員
  clockToleranceSec: 5,
});
```

多租戶（一個服務同時服務好幾個 app，像 selfize）用 `allowedClaims`：

```js
const auth = createJwksVerifier({
  jwksUrl: process.env.LETMEUSE_JWKS_URL,
  allowedClaims: { app: ['app_one', 'app_two'] },   // 空陣列 = 拒絕全部
});
```

### 健檢要把狀態露出來

fail-closed 若不可觀測，IdP 一掛就是「全部 401 且零線索」：

```js
if (url.pathname === '/api/health') {
  // 刻意回 200 而不是 503：重啟本服務救不了上游，而監控探的就是這支，
  // 回 5xx 只會換來無用的重啟迴圈。
  return json(res, { ok: true, jwks: auth.stats() });
}
```

`stats()` 回 `{ url, keys, kids, lastMissKid, stale, lastSuccessAt, lastAttemptAt, lastError }`。
`kids` 和 `lastMissKid` 存在的理由：最常見的事故形狀是「輪換後 token 的 `kid` 不在快取裡」，而光一個 `keys: 1` 分不出它跟健康快取的差別。

### Next.js / serverless：改用 async 版

`verifySync` 在快取還冷的時候一定 fail-closed，所以需要開機預熱。但 Next.js 可能把 `instrumentation.ts` 和 route handler 打包成**不同 module 實例**，預熱到的是另一份快取——這種環境請用 `verifyAsync()`，它會在 miss 時等一次有逾時的抓取：

```js
const claims = await auth.verifyAsync(token);   // 重啟後第一個請求也會成功
```

> 它刻意**不叫** `verify`。忘了 `await` 的話 `if (!claims)` 會拿到一個 truthy 的 Promise，請求就被當成已驗證放行（而 `claims.sub` 是 `undefined`）。短而順手的名字不該是那顆地雷，所以這個 kit 沒有 `verify` 這個方法。

## API

`createJwksVerifier(options)` / `createLetMeUseVerifier(options)` → verifier

所有數字選項都必須是 **>= 0 的有限數字**，否則建構時就 throw——`NaN`（最常見來源：`Number(process.env.X)` 而 env 沒設）會靜默關掉對應的保護。`0` 是合法的「明確關閉」。

| option | 預設 | 說明 |
|---|---|---|
| `jwksUrl` | — | 完整 JWKS 網址（優先）。必須是 `https`，localhost 例外 |
| `baseUrl` + `jwksPath` | `/.well-known/jwks.json`（LetMeUse 版為 `/api/jwks`） | 或用 base 組 |
| `allowInsecureHttp` | `false` | 真的要對外明文時才打開 |
| `algorithms` | `["ES256"]` | 白名單。支援 `ES256` / `ES384` / `ES512`；型別錯或不支援都 throw |
| `issuer` | — | 給了就比對 `iss`；給空字串 = 拒絕全部 |
| `requiredClaims` | — | claim 必須**相等**；期望值為空 = 拒絕全部。只有 `aud` 例外（見下） |
| `allowedClaims` | — | claim 必須落在陣列裡（多租戶用）；空陣列 = 拒絕全部 |
| `requireSubject` | `true` | 要求 `sub` 是非空字串 |
| `clockToleranceSec` | `0` | exp/nbf 容許的時鐘誤差（秒） |
| `refreshMs` | `3600000` | 定時刷新；`0` = 不定時 |
| `missCooldownMs` | `60000` | 未知 kid 最快多久重抓一次 |
| `minRefreshIntervalMs` | `0`（不節流） | 手動 `refresh()` 的節流。**預設關閉**：預設會節流又靜默的話，「金鑰外洩→從 JWKS 下架→`refresh()` 立刻生效」這條路會被無聲吃掉。要這道閘就自己設，並看 `refresh()` 回傳的 `throttled` |
| `now` | `Date.now` | **只有 `createJwksCache` 收**。注入時鐘（毫秒），只影響政策計時（冷卻／stale／節流），不影響抓取逾時。沒有它的話冷卻這類行為只能「設成 0」或「真的等 60 秒」來測，實務上就是沒測 |
| `timeoutMs` | `5000` | 抓 JWKS 的總預算（fetch 與 json 共用同一個期限） |
| `maxStaleMs` | `86400000` | 連續抓不到這麼久就當作沒金鑰 |
| `maxKeys` | `50` | JWKS 金鑰數上限（`createPublicKey` 不便宜，兩萬把會阻塞 event loop 一秒多） |
| `fetchImpl` | `globalThis.fetch` | 測試可注入 |
| `onError` | `console.error` | fail-closed 的原因往這裡送。預設大聲，安靜的 fail-closed 就是無聲故障 |
| `autoStart` | `true` | 建好就開始抓並定時刷新 |

| verifier | 說明 |
|---|---|
| `verifySync(token)` | → claims 或 `null`。同步，冷快取時 fail-closed |
| `await verifyAsync(token)` | 同上，但 miss 時等一次抓取。**刻意不叫 `verify`** |
| `bearer(authorizationHeader)` | → token 或 `null`（scheme 依 RFC 6750 不分大小寫） |
| `await ready()` | 開機預熱，回傳 `stats()`。`ready({ strict: true })` 在預熱失敗時 reject |
| `stats()` | 診斷狀態，掛上 /health |
| `refresh()` / `whenIdle()` / `stop()` | 手動刷新 / 等背景抓完 / 收掉定時器（之後 `ready()` 會重新裝回去） |
| `getKey(kid)` / `getKeyAsync(kid)` / `jwksUrl` | 低階存取 |

### 兩個 claim 選項對「陣列」的處理刻意不同

- `requiredClaims` 只有 **`aud`** 在 token 的值是陣列時做成員比對（RFC 7519 §4.1.3 就這麼定義）。其他 claim 一律嚴格相等 —— 包含租戶 claim。若 `app` 也接受「集合包含」，一顆 `app: ["app_mine","app_other"]` 的 token 就能同時通過兩個租戶的驗證，而它是簽名有效的真 token，沒有任何線索。
- `allowedClaims` 是反方向（token 的單一值必須落在清單裡），token 的 claim 本身是陣列時一律拒絕。它是租戶邊界用的，寧可拒絕也不去猜「陣列裡命中一個算不算通過」。

⚠️ `verifySync` / `verifyAsync` **沒有**「每次呼叫覆寫選項」的第二參數。淺層 spread 會讓呼叫端把建構時設好的 `requiredClaims` / `issuer` / `exp` 檢查整個換掉，而那形狀很自然（「這條路由還要額外 `role: admin`」）——要逐路由加條件請另建一個 verifier。

低階積木也有匯出：`createJwksCache`、`verifyJwt`、`verifyJwtAsync`、`bearerToken`。

## 測試

```bash
npm test      # 80 個，零依賴
npm run example
```

## License

MIT © Jeffrey0117
