// 選項驗證。
//
// 為什麼要大聲 throw 而不是悄悄套預設值：這個 kit 的每個數字選項，非正值都
// 代表「關掉某個保護」。`timeoutMs: Number(process.env.JWKS_TIMEOUT_MS)` 在
// env 沒設時是 `NaN` → `!(NaN > 0)` 為真 → 逾時整個消失 → 卡死的 fetch 讓
// promise 永不 settle、in-flight 旗標永久占住、所有人 401 且零診斷。那正是
// 這個 kit 寫出來要消滅的那個 bug，不能讓一行漏掉的 env 把它放回來。
//
// `0` 仍然是合法的「明確關閉」值（文件有寫），但必須是真的寫 0，不是 NaN。

/** 非負有限數字，或 undefined/null → fallback。其餘 throw。 */
function num(name, value, fallback) {
  if (value === undefined || value === null) return fallback;
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new Error(
      `jwks-verify-kit: ${name} 必須是 >= 0 的有限數字（收到 ${JSON.stringify(value)}）。`
      + "非正值會關掉對應的保護，所以不接受 NaN／負數／字串。",
    );
  }
  return value;
}

/** 純物件（不是陣列、不是字串、不是函式）。undefined/null 代表沒設。 */
function plainObjectOrNull(name, value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new Error(
      `jwks-verify-kit: ${name} 必須是物件（收到 ${typeof value}）。`
      + "這是租戶／受眾邊界，設錯型別會讓整個檢查消失，所以寧可壞得大聲。",
    );
  }
  return value;
}

/**
 * 淺拷貝 + 凍結。宿主傳進來的物件如果之後被它自己改動，驗證結果會跟著變
 * （實測：宿主改掉它傳入的 requiredClaims 之後，原本有效的 token 開始回 null）。
 */
function freezeCopy(value) {
  return value === null ? null : Object.freeze({ ...value });
}

module.exports = { num, plainObjectOrNull, freezeCopy };
