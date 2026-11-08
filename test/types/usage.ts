// 型別宣告的驗證：這個檔案本身就是測試 —— `tsc --noEmit` 過了，才代表五個 TS
// 專案（pokkit / upimg / pdfluv / plottr / areyoubot）import 得起來。
//
// 這裡刻意照「真實專案會怎麼寫」來寫，而不是照宣告檔逐項對照：型別檔的 bug
// 幾乎都長成「真的那樣用的時候才爆」。
import {
  createJwksVerifier,
  createLetMeUseVerifier,
  createJwksCache,
  verifyJwt,
  verifyJwtAsync,
  bearerToken,
  SUPPORTED_ALGS,
  type Claims,
  type JwksStats,
  type JwksVerifier,
} from "jwks-verify-kit";
import crypto from "node:crypto";

// ── 1. LetMeUse 預設版（pokkit / upimg / pdfluv / plottr / areyoubot 的用法）──
const lmu: JwksVerifier = createLetMeUseVerifier({
  appId: process.env.LETMEUSE_APP_ID,
  baseUrl: process.env.LETMEUSE_BASE_URL,
  timeoutMs: Number(process.env.JWKS_TIMEOUT_MS) || 5000,
  onError: (err: Error) => console.warn(err.message),
});

// 同步路徑（pokkit / quickky / plottr / speakslow-stats / wemeet）
const claims: Claims | null = lmu.verifySync("a.b.c");
if (claims) {
  const sub: string = typeof claims.sub === "string" ? claims.sub : "";
  const email: string = typeof claims.email === "string" ? claims.email : "";
  void sub;
  void email;
}

// 非同步路徑（pdfluv / areyoubot / takeenglish —— Next.js 保證不了開機預熱）
async function routeHandler(authorization: string | null): Promise<number> {
  const token = lmu.bearer(authorization);
  if (!token) return 401;
  const c = await lmu.verifyAsync(token);
  if (!c) return 401;
  return 200;
}
void routeHandler;

// 健檢（公開版只能給最小狀態）
async function health() {
  const s: JwksStats = await lmu.ready();
  return { ok: s.keys > 0, keys: s.keys, degraded: s.stale };
}
void health;

// 開機預熱要炸的版本
async function boot() {
  const s = await lmu.ready({ strict: true });
  console.log(s.kids.join(","));
}
void boot;

lmu.stop();
void lmu.refresh();
void lmu.whenIdle();
const jwksUrl: string = lmu.jwksUrl;
void jwksUrl;

// ── 2. 多租戶（selfize 的用法：一個 verifier 服務多個 app）──────────────────
const multi = createJwksVerifier({
  jwksUrl: "https://idp.example.com/api/jwks",
  algorithms: ["ES256"],
  allowedClaims: { app: ["app_a", "app_b"] },
  requireSubject: true,
  clockToleranceSec: 5,
});
void multi.verifySync("x.y.z");

// ── 3. 低階積木（測試注入金鑰 / 假時鐘：plottr、speakslow-stats、areyoubot）──
declare const key: crypto.KeyObject;
const pure: Claims | null = verifyJwt("a.b.c", {
  getKey: (kid: string) => (kid === "k1" ? key : null),
  algorithms: ["ES256"],
  requiredClaims: { app: "app_x" },
  now: 1_700_000_000,
});
void pure;

async function pureAsync() {
  const c = await verifyJwtAsync("a.b.c", {
    getKey: async (kid: string) => (kid ? key : null),
    requiredClaims: { app: "app_x" },
  });
  return c;
}
void pureAsync;

const cache = createJwksCache({ url: "https://idp.example.com/api/jwks", timeoutMs: 3000 });
const k: crypto.KeyObject | null = cache.getKey("k1");
void k;
void cache.getKeyAsync("k1");
void cache.start();
cache.stop();

const b: string | null = bearerToken("Bearer abc");
void b;
const algs: readonly string[] = SUPPORTED_ALGS;
void algs;
