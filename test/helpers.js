const crypto = require("node:crypto");

/** 模擬 IdP 的簽章金鑰組。驗證端永遠只拿到 public 那半 —— 這就是 ES256 的重點。 */
function keypair(namedCurve = "prime256v1") {
  return crypto.generateKeyPairSync("ec", { namedCurve });
}

function b64(obj) {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

/**
 * 簽一顆真的 ES256 token。簽章是 raw r||s（"ieee-p1363"）—— JWS 規定如此，
 * 也是 jose 的 SignJWT 會吐的格式；DER 不會通過驗證。
 */
function signToken(payload, opts = {}) {
  const alg = opts.alg || "ES256";
  const digest = { ES256: "sha256", ES384: "sha384", ES512: "sha512" }[alg] || "sha256";
  const header = { alg, typ: "JWT", kid: "test-kid", ...(opts.header || {}) };
  if (opts.header && "kid" in opts.header && opts.header.kid === undefined) delete header.kid;
  const input = `${b64(header)}.${b64(payload)}`;
  const sig = crypto.sign(digest, Buffer.from(input), {
    key: opts.key,
    ...(opts.der ? {} : { dsaEncoding: "ieee-p1363" }),
  });
  return `${input}.${sig.toString("base64url")}`;
}

/** 舊世界的 HS256 token，用（可能已外洩的）app secret 簽。 */
function signHs256(payload, secret, header = {}) {
  const input = `${b64({ alg: "HS256", typ: "JWT", ...header })}.${b64(payload)}`;
  const sig = crypto.createHmac("sha256", secret).update(input).digest("base64url");
  return `${input}.${sig}`;
}

/** 公鑰 → JWK（JWKS 回應用）。 */
function toJwk(publicKey, kid = "test-kid", extra = {}) {
  return { ...publicKey.export({ format: "jwk" }), kid, use: "sig", ...extra };
}

/** 假的 fetch：回固定的 JWKS 回應，並記錄被呼叫幾次。 */
function fakeFetch(bodyOrFn, opts = {}) {
  const calls = [];
  const impl = async (url, init) => {
    calls.push({ url, init });
    const body = typeof bodyOrFn === "function" ? bodyOrFn(calls.length) : bodyOrFn;
    if (body instanceof Error) throw body;
    return {
      ok: opts.ok !== false,
      status: opts.status || 200,
      json: async () => body,
    };
  };
  impl.calls = calls;
  return impl;
}

const nowSec = () => Math.floor(Date.now() / 1000);

module.exports = { keypair, signToken, signHs256, toJwk, fakeFetch, b64, nowSec };
