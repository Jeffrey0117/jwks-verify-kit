// 允許的簽章演算法表。
//
// 🔒 刻意只收 ECDSA 家族，而且是白名單而非黑名單：
//   - `alg: "none"` → 不在表裡 → 擋掉
//   - `HS256`（對稱）→ 不在表裡 → 擋掉。這是整個 kit 存在的理由：對稱簽章
//     等於「驗證方必須握著簽發金鑰」，secret 一外洩就能自簽任意身分。
//     （Jeff 生態系 2026-10-25 pokkit 事件根因。）
//   - `RS256` → 刻意不收。不是因為它不安全，而是因為收了就要處理 RSA 的
//     PSS/PKCS1 padding 分支，而目前生態系的 IdP（LetMeUse）只發 ES256。
//     真的需要時在這裡加一列，並補對應的 verify 參數與測試。
//
// sigBytes = 曲線位元組 × 2（r||s）。JWS 規定 ECDSA 簽章是 raw r||s，
// **不是** DER —— 長度檢查順手把 DER 編碼的簽章擋掉（DER 會多幾個位元組）。
// b64urlChars = 不帶 padding 的 base64url 長度，用來在解碼前就擋掉廢物。
// nodeCurves = node `asymmetricKeyDetails.namedCurve` 可能回的名字（OpenSSL
// 的短名與 JWK 的 crv 寫法不同，兩者都收）。

const ALGORITHMS = Object.freeze({
  ES256: Object.freeze({
    digest: "sha256", crv: "P-256", sigBytes: 64, b64urlChars: 86,
    nodeCurves: Object.freeze(["prime256v1", "P-256", "secp256r1"]),
  }),
  ES384: Object.freeze({
    digest: "sha384", crv: "P-384", sigBytes: 96, b64urlChars: 128,
    nodeCurves: Object.freeze(["secp384r1", "P-384"]),
  }),
  ES512: Object.freeze({
    // ⚠️ ES512 的曲線是 P-521，不是 P-512。簽章 2×66 = 132 bytes。
    digest: "sha512", crv: "P-521", sigBytes: 132, b64urlChars: 176,
    nodeCurves: Object.freeze(["secp521r1", "P-521"]),
  }),
});

const SUPPORTED_ALGS = Object.freeze(Object.keys(ALGORITHMS));

// 預設白名單。只放一份，三個呼叫點都引用這裡（原本各寫一次 ["ES256"]）。
const DEFAULT_ALGS = Object.freeze(["ES256"]);

/** JWK 的 crv → 支援的 alg 名稱（給 JWKS 載入時檢查金鑰型別用）。 */
const CRV_TO_ALG = Object.freeze({
  "P-256": "ES256",
  "P-384": "ES384",
  "P-521": "ES512",
});

module.exports = { ALGORITHMS, SUPPORTED_ALGS, DEFAULT_ALGS, CRV_TO_ALG };
