// 負面型別測試。`@ts-expect-error` 的語意是反的：**如果下一行沒有報錯，tsc 自己
// 就會失敗**。所以這個檔案是「宣告檔真的擋得住這些寫法」的證明，而不是又一次
// 「寫對了所以綠燈」。
//
// 一份太鬆的 .d.ts（全部 any）會讓上面的 usage.ts 永遠綠燈卻毫無保護力 ——
// 這就是 testing.md 說的「對壞碼跟好碼都綠的測試比沒測試更糟」。
import { createLetMeUseVerifier, createJwksVerifier, verifyJwt } from "jwks-verify-kit";

const lmu = createLetMeUseVerifier({ appId: "app_x", baseUrl: "https://idp.example.com" });

// ── 1. 最貴的那個錯：忘了 await。verifyAsync 回 Promise，永遠 truthy ────────
//     真實事故形狀：README 寫 `if (!claims) return 401`，而 claims 是 Promise
//     → 每一顆 token 都放行。宣告檔必須讓這行在編譯時就爆。
async function forgotAwait(token: string) {
  const claims = lmu.verifyAsync(token);
  // @ts-expect-error Promise 沒有 .sub —— 忘了 await 要在這裡爆，不是上線後才發現
  return claims.sub;
}
void forgotAwait;

// ── 2. 沒判 null 就取用 claims ──────────────────────────────────────────────
function forgotNullCheck(token: string) {
  const claims = lmu.verifySync(token);
  // @ts-expect-error claims 可能是 null，這個 kit 的全部重點就是這個 null
  return claims.sub;
}
void forgotNullCheck;

// ── 3. 不支援的 alg（RSA 是刻意不收的：alg 混淆面太大）────────────────────
createJwksVerifier({
  jwksUrl: "https://idp.example.com/api/jwks",
  // @ts-expect-error RS256 不在白名單內
  algorithms: ["RS256"],
});

// ── 4. 以為有「每次呼叫覆寫選項」的第二參數 ─────────────────────────────────
//     那個參數被刻意移除：淺層 spread 會讓呼叫端把建構時設好的 requiredClaims
//     整個換掉（= 把租戶邊界關掉），所以它不該存在。
// @ts-expect-error verifySync 只收一個參數
void lmu.verifySync("a.b.c", { requiredClaims: {} });

// ── 5. 舊名字 `verify`（曾經存在、且就是上面那個 Promise 坑）不該還在 ───────
// @ts-expect-error 沒有 verify 這個方法，只有 verifySync / verifyAsync
void lmu.verify("a.b.c");

// ── 6. verifyJwt 沒給 getKey ────────────────────────────────────────────────
// @ts-expect-error getKey 必填，少了它會 fail-closed 拒絕全部（要編譯期就知道）
void verifyJwt("a.b.c", { algorithms: ["ES256"] });

// ── 7. allowedClaims 的值必須是陣列（給單一字串是很自然的筆誤）─────────────
createJwksVerifier({
  jwksUrl: "https://idp.example.com/api/jwks",
  // @ts-expect-error 要 string[]，不是 string
  allowedClaims: { app: "app_x" },
});
