import type { Rule } from "./types.js";
export type { Rule };
/**
 * Named rules compiled from gitleaks TOML (MIT) + clean-room additions.
 * All regexes are pre-compiled at build time.
 *
 * Secret detection rules vendored from gitleaks/gitleaks (MIT License)
 * https://github.com/gitleaks/gitleaks
 */
export declare const NAMED_RULES: Rule[];
/**
 * Clean-room additions for providers not covered by gitleaks.
 * Independently written — no code copied from any AGPL source.
 */
export declare const CLEAN_ROOM_RULES: Rule[];
/**
 * Entropy-based rules for catching high-entropy strings that don't match named patterns.
 * Approach inspired by detect-secrets (Apache-2.0), independently implemented.
 */
export declare const ENTROPY_RULES: Rule[];
//# sourceMappingURL=rules.d.ts.map