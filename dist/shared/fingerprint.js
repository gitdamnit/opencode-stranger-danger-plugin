import { createHash } from "node:crypto";
/**
 * Produces a deterministic 8-character fingerprint from any string.
 * Uses SHA-256 truncated to the first 8 hex characters.
 * Same input always produces the same output.
 */
export function fingerprint(value) {
    return createHash("sha256").update(value).digest("hex").slice(0, 8);
}
//# sourceMappingURL=fingerprint.js.map