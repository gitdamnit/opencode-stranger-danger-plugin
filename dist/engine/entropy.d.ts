/**
 * Shannon entropy calculator — clean-room implementation.
 * Algorithm: H = -sum(p * log2(p)) for each character frequency.
 * Reference concept from detect-secrets (Apache-2.0), independently implemented.
 */
/**
 * Calculate Shannon entropy of a string using all characters present in it.
 */
export declare function shannonEntropy(data: string): number;
/**
 * Check if a string only contains characters from a given charset.
 */
export declare function matchesCharset(data: string, charset: string): boolean;
/**
 * Base64 charset: A-Z, a-z, 0-9, +, /, =, -, _
 */
export declare const BASE64_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_";
/**
 * Hex charset: 0-9, a-f, A-F
 */
export declare const HEX_CHARSET = "0123456789abcdefABCDEF";
/**
 * Alphanumeric charset: A-Z, a-z, 0-9
 */
export declare const ALPHANUMERIC_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
/**
 * Check if a string has high entropy.
 * First verifies the string only contains charset characters,
 * then checks if entropy exceeds the threshold.
 */
export declare function isHighEntropy(data: string, charset: string, threshold: number, minLength: number): boolean;
//# sourceMappingURL=entropy.d.ts.map