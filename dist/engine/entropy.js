/**
 * Shannon entropy calculator — clean-room implementation.
 * Algorithm: H = -sum(p * log2(p)) for each character frequency.
 * Reference concept from detect-secrets (Apache-2.0), independently implemented.
 */
/**
 * Calculate Shannon entropy of a string using all characters present in it.
 */
export function shannonEntropy(data) {
    if (data.length === 0)
        return 0;
    const freq = new Map();
    for (const char of data) {
        freq.set(char, (freq.get(char) || 0) + 1);
    }
    let entropy = 0;
    const len = data.length;
    for (const count of freq.values()) {
        const p = count / len;
        if (p > 0) {
            entropy -= p * Math.log2(p);
        }
    }
    return entropy;
}
/**
 * Check if a string only contains characters from a given charset.
 */
export function matchesCharset(data, charset) {
    const charsetSet = new Set(charset);
    for (const char of data) {
        if (!charsetSet.has(char))
            return false;
    }
    return true;
}
/**
 * Base64 charset: A-Z, a-z, 0-9, +, /, =, -, _
 */
export const BASE64_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_";
/**
 * Hex charset: 0-9, a-f, A-F
 */
export const HEX_CHARSET = "0123456789abcdefABCDEF";
/**
 * Alphanumeric charset: A-Z, a-z, 0-9
 */
export const ALPHANUMERIC_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
/**
 * Check if a string has high entropy.
 * First verifies the string only contains charset characters,
 * then checks if entropy exceeds the threshold.
 */
export function isHighEntropy(data, charset, threshold, minLength) {
    if (data.length < minLength)
        return false;
    if (!matchesCharset(data, charset))
        return false;
    return shannonEntropy(data) >= threshold;
}
//# sourceMappingURL=entropy.js.map