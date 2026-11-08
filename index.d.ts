// TypeScript 宣告 — 不需要安裝 @types，這個檔案就是型別。
//
// 為什麼要有這份：生態系裡有五個 TS 專案（pokkit / upimg / pdfluv / plottr /
// areyoubot）會跑 `tsc` 或 `next build`。沒有宣告檔的話 `import` 這個 kit 會在
// 建置時爆 TS7016（找不到宣告檔），而 cloudpipe 的部署看到 build 失敗就把那個
// commit 丟進 failedCommits 黑名單 —— 等於「kit 本身沒錯，但誰都裝不起來」。
//
// 這裡刻意把回傳型別寫成 `Claims | null` 而不是 `any`：呼叫端忘了判 null 時
// TS 就會在 `claims.sub` 那行報錯。那個 null 檢查就是這個 kit 的全部重點。

import type { KeyObject } from "node:crypto";

/** 解出來的 JWT claims。原型是 null（擋 prototype pollution），所以用索引型別。 */
export type Claims = Record<string, unknown> & {
  sub?: string;
  exp?: number;
  nbf?: number;
  iat?: number;
  iss?: string;
  aud?: string | string[];
  app?: string;
  email?: string;
  name?: string;
  role?: string;
};

export type SupportedAlg = "ES256" | "ES384" | "ES512";

export interface JwksStats {
  /** 實際在抓的 JWKS 網址。 */
  readonly url: string;
  /** 快取裡的金鑰數。**0 = 每一顆 token 都會被拒絕。** */
  readonly keys: number;
  /** 快取裡的 kid（公開資訊）。輪換事故時用來跟 token 的 kid 對照。 */
  readonly kids: readonly string[];
  /**
   * 最近一次「要的 kid 不在快取裡」的那個 kid。
   * ⚠️ 這是呼叫端送來的值，**不要原樣放進公開端點**（會變成反射式資訊外洩）。
   */
  readonly lastMissKid: string | null;
  /** 距上次成功抓取已超過 maxStaleMs。 */
  readonly stale: boolean;
  readonly lastSuccessAt: number | null;
  readonly lastAttemptAt: number | null;
  readonly lastError: string | null;
}

export interface JwksCacheOptions {
  /** JWKS 完整網址。非 https 會被拒絕（localhost 除外）。 */
  jwksUrl?: string;
  /** 服務根網址，會接上 jwksPath。 */
  baseUrl?: string;
  /** 預設 `/.well-known/jwks.json`；LetMeUse 預設版是 `/api/jwks`。 */
  jwksPath?: string;
  /** 允許用明文 http 抓 JWKS。**信任根可被中間人替換**，只在隔離網路用。 */
  allowInsecureHttp?: boolean;
  /** 允許的 alg 白名單，預設 `["ES256"]`。 */
  algorithms?: readonly SupportedAlg[];
  /** 定時刷新間隔（ms）。 */
  refreshMs?: number;
  /** 未知 kid 觸發重抓的冷卻（ms），從抓取**結束**算起。 */
  missCooldownMs?: number;
  /** 手動 refresh() 的節流（ms）。 */
  minRefreshIntervalMs?: number;
  /** 單次抓取逾時（ms）。node 的 fetch 沒有預設逾時，所以這個一定要有。 */
  timeoutMs?: number;
  /** 超過這段時間沒成功抓到就算 stale（ms）。 */
  maxStaleMs?: number;
  /** 一份 JWKS 最多收幾把金鑰。 */
  maxKeys?: number;
  /** 注入 fetch（測試用）。 */
  fetchImpl?: typeof fetch;
  /** 抓取失敗的回呼。預設 `console.error`。 */
  onError?: (err: Error) => void;
  /** false = 不在建構時就開始抓（之後自己呼叫 ready()）。 */
  autoStart?: boolean;
}

export interface VerifyClaimOptions {
  /** 要求 `iss` 等於這個值。 */
  issuer?: string;
  /**
   * 要求這些 claim 完全相等（`aud` 例外：token 的 aud 是陣列時用包含比對）。
   * 值不可以是 undefined / null / 空字串 —— 那會讓整條檢查靜默消失，所以直接拒絕。
   */
  requiredClaims?: Record<string, unknown>;
  /** 要求這些 claim 落在允許清單內。**空陣列＝拒絕全部**（多租戶白名單用）。 */
  allowedClaims?: Record<string, readonly unknown[]>;
  /** 預設 true：要求非空字串 `sub`。 */
  requireSubject?: boolean;
  /** 時鐘誤差容許（秒）。 */
  clockToleranceSec?: number;
}

export type JwksVerifierOptions = JwksCacheOptions & VerifyClaimOptions;

export interface JwksVerifier {
  /**
   * 同步驗證。快取 miss 一律 fail-closed（背景補抓）。
   * 用這支的服務必須在開機時 `await ready()`，否則重啟後第一個請求會 401。
   */
  verifySync(token: string | null | undefined): Claims | null;
  /**
   * 非同步驗證：快取 miss 時等一次（有逾時的）抓取。
   * 無法保證開機預熱的環境（Next.js / serverless）用這支。
   *
   * ⚠️ 回傳 Promise —— `if (!verifier.verifyAsync(t)) return 401` 永遠是 truthy，
   * 一定要 `await`。
   */
  verifyAsync(token: string | null | undefined): Promise<Claims | null>;
  /** 從 Authorization header 取 Bearer token（scheme 不分大小寫）。 */
  bearer(authorization: string | null | undefined): string | null;
  /**
   * 開機預熱。⚠️ IdP 掛掉時**也會 resolve**（失敗是記錄不是拋），所以別把
   * 「resolve 了」讀成「金鑰載好了」—— 看回傳的 `keys`。要失敗就炸傳 strict。
   */
  ready(opts?: { strict?: boolean }): Promise<JwksStats>;
  /** 收掉定時器。之後再 ready() 會重新裝回去。 */
  stop(): void;
  /** 手動重抓（有節流）。 */
  refresh(): Promise<void>;
  /** 等背景那次抓取結束（測試用）。 */
  whenIdle(): Promise<void>;
  /** 診斷狀態。放進健檢端點，但公開版要篩過（見 JwksStats.lastMissKid）。 */
  stats(): JwksStats;
  getKey(kid: string): KeyObject | null;
  getKeyAsync(kid: string): Promise<KeyObject | null>;
  readonly jwksUrl: string;
}

export interface JwksCache {
  getKey(kid: string): KeyObject | null;
  getKeyAsync(kid: string): Promise<KeyObject | null>;
  refresh(): Promise<void>;
  whenIdle(): Promise<void>;
  stats(): JwksStats;
  start(): Promise<void>;
  stop(): void;
  readonly url: string;
}

/** 泛用版：自己給網址與 claim 條件。 */
export function createJwksVerifier(options?: JwksVerifierOptions): JwksVerifier;

export interface LetMeUseVerifierOptions extends JwksVerifierOptions {
  /**
   * **必填**（或設 `LETMEUSE_APP_ID`），缺了直接 throw。
   * LetMeUse 用同一把 ES256 金鑰簽發所有 app 的 token，`app` claim 是唯一的
   * 租戶邊界 —— 少了它不是少一道檢查，而是任何 app 的任何使用者都能進來。
   */
  appId?: string;
}

/**
 * LetMeUse 專用預設：jwksPath `/api/jwks`，並把 `app: appId` 釘成必要 claim。
 * appId 或網址缺一個就在啟動時 throw（不是靜默變成「永遠拒絕所有人」）。
 */
export function createLetMeUseVerifier(options?: LetMeUseVerifierOptions): JwksVerifier;

export function createJwksCache(options: JwksCacheOptions & { url: string }): JwksCache;

export interface VerifyJwtOptions extends VerifyClaimOptions {
  getKey: (kid: string) => KeyObject | null;
  algorithms?: readonly SupportedAlg[];
  /** 覆寫「現在」（秒）。測試用。 */
  now?: number;
}

export interface VerifyJwtAsyncOptions extends Omit<VerifyJwtOptions, "getKey"> {
  getKey: (kid: string) => KeyObject | null | Promise<KeyObject | null>;
}

/** 純驗證，自己提供 getKey。測試要注入金鑰或假時鐘時用這支。 */
export function verifyJwt(token: string | null | undefined, options: VerifyJwtOptions): Claims | null;
export function verifyJwtAsync(
  token: string | null | undefined,
  options: VerifyJwtAsyncOptions,
): Promise<Claims | null>;

export function bearerToken(authorization: string | null | undefined): string | null;

export const SUPPORTED_ALGS: readonly SupportedAlg[];
