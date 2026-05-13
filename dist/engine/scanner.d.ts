import type { Finding } from "./types.js";
/**
 * Scan content against all rules and return findings.
 */
export declare function scan(content: string, source: Finding["source"], filePath?: string): Finding[];
/**
 * Redact all findings in the content, replacing each secret with its redaction token.
 * Overlapping matches are handled by keeping the earliest (lowest offset) match.
 */
export declare function redact(content: string, findings: Finding[]): string;
/**
 * Scan and redact in one step. Returns the redacted content and the findings.
 */
export declare function scanAndRedact(content: string, source: Finding["source"], filePath?: string): {
    redacted: string;
    findings: Finding[];
};
//# sourceMappingURL=scanner.d.ts.map