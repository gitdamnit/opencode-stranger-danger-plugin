import { NAMED_RULES, ENTROPY_RULES, CLEAN_ROOM_RULES } from "./rules.js";
import { shannonEntropy, BASE64_CHARSET, HEX_CHARSET, matchesCharset } from "./entropy.js";
import { filterByAllowlist, loadAllowlist } from "./allowlist.js";
import { fingerprint } from "../shared/fingerprint.js";
const REDACTION_PREFIX = "[REDACTED:";
const REDACTION_SUFFIX = "]";
function makeRedactionToken(ruleId, value) {
    return `${REDACTION_PREFIX}${ruleId}:${fingerprint(value)}${REDACTION_SUFFIX}`;
}
/**
 * Deduplicate findings by preferring shorter/more specific matches.
 * When multiple rules match overlapping regions, the shortest match (most specific) wins.
 */
function deduplicateFindings(findings) {
    if (findings.length <= 1)
        return findings;
    // Sort by:
    // 1. Match length ascending (shorter/more-specific wins)
    // 2. Offset ascending (earlier first)
    // 3. Non-generic rules before generic ones (specific wins)
    const GENERIC_RULES = new Set(["generic-api-key", "generic-api-key-2"]);
    const sorted = [...findings].sort((a, b) => {
        const lenDiff = a.match.length - b.match.length;
        if (lenDiff !== 0)
            return lenDiff;
        const offsetDiff = a.offset - b.offset;
        if (offsetDiff !== 0)
            return offsetDiff;
        // Prefer specific (non-generic) rules over generic ones
        const aGeneric = GENERIC_RULES.has(a.ruleId);
        const bGeneric = GENERIC_RULES.has(b.ruleId);
        if (aGeneric !== bGeneric)
            return aGeneric ? 1 : -1;
        return a.ruleId.localeCompare(b.ruleId);
    });
    const deduped = [];
    for (const finding of sorted) {
        const fStart = finding.offset;
        const fEnd = finding.offset + finding.match.length;
        // Skip if this finding overlaps with any already-kept (shorter/more specific) finding
        const overlaps = deduped.some((kept) => {
            const kStart = kept.offset;
            const kEnd = kept.offset + kept.match.length;
            return fStart < kEnd && fEnd > kStart;
        });
        if (!overlaps) {
            deduped.push(finding);
        }
    }
    // Return sorted by offset for deterministic output
    return deduped.sort((a, b) => a.offset - b.offset);
}
function hasKeyword(text, keywords) {
    const lower = text.toLowerCase();
    return keywords.some((kw) => lower.includes(kw.toLowerCase()));
}
/**
 * Scan content against all rules and return findings.
 */
export function scan(content, source, filePath) {
    const findings = [];
    for (const rule of [...NAMED_RULES, ...CLEAN_ROOM_RULES]) {
        rule.regex.lastIndex = 0;
        let match;
        while ((match = rule.regex.exec(content)) !== null) {
            const secretValue = match[1] ?? match[0];
            const offset = match[1] !== undefined
                ? match.index + match[0].indexOf(match[1])
                : match.index;
            if (secretValue.length < 6) {
                rule.regex.lastIndex = match.index + 1;
                continue;
            }
            if (rule.keywords.length > 0) {
                const contextStart = Math.max(0, offset - 80);
                const contextEnd = Math.min(content.length, offset + secretValue.length + 80);
                const context = content.slice(contextStart, contextEnd);
                if (!hasKeyword(context, rule.keywords)) {
                    rule.regex.lastIndex = match.index + 1;
                    continue;
                }
            }
            if (rule.entropy !== undefined) {
                const entropy = shannonEntropy(secretValue);
                if (entropy < rule.entropy) {
                    rule.regex.lastIndex = match.index + 1;
                    continue;
                }
            }
            findings.push({
                ruleId: rule.id,
                description: rule.description,
                match: secretValue,
                redacted: makeRedactionToken(rule.id, secretValue),
                offset,
                source,
                ...(filePath ? { filePath } : {}),
            });
        }
    }
    for (const rule of ENTROPY_RULES) {
        rule.regex.lastIndex = 0;
        let match;
        while ((match = rule.regex.exec(content)) !== null) {
            const candidate = match[1] ?? match[0];
            const offset = match[1] !== undefined
                ? match.index + match[0].indexOf(match[1])
                : match.index;
            if (candidate.length < 20) {
                rule.regex.lastIndex = match.index + 1;
                continue;
            }
            let threshold = 4.0;
            if (matchesCharset(candidate, BASE64_CHARSET)) {
                threshold = 4.5;
            }
            else if (matchesCharset(candidate, HEX_CHARSET)) {
                threshold = 3.0;
            }
            const entropy = shannonEntropy(candidate);
            if (entropy < threshold) {
                rule.regex.lastIndex = match.index + 1;
                continue;
            }
            findings.push({
                ruleId: rule.id,
                description: rule.description,
                match: candidate,
                redacted: makeRedactionToken(rule.id, candidate),
                offset,
                source,
                ...(filePath ? { filePath } : {}),
            });
        }
    }
    return deduplicateFindings(findings);
}
/**
 * Redact all findings in the content, replacing each secret with its redaction token.
 * Overlapping matches are handled by keeping the earliest (lowest offset) match.
 */
export function redact(content, findings) {
    if (findings.length === 0)
        return content;
    const sorted = [...findings].sort((a, b) => a.offset - b.offset);
    const nonOverlapping = [];
    let lastEnd = 0;
    for (const finding of sorted) {
        if (finding.offset >= lastEnd) {
            nonOverlapping.push(finding);
            lastEnd = finding.offset + finding.match.length;
        }
    }
    let result = "";
    let prevEnd = 0;
    for (const finding of nonOverlapping) {
        result += content.slice(prevEnd, finding.offset);
        result += finding.redacted;
        prevEnd = finding.offset + finding.match.length;
    }
    result += content.slice(prevEnd);
    return result;
}
/**
 * Scan and redact in one step. Returns the redacted content and the findings.
 */
export function scanAndRedact(content, source, filePath) {
    const rawFindings = scan(content, source, filePath);
    const allowlist = loadAllowlist();
    const findings = filterByAllowlist(rawFindings, allowlist);
    const redacted = redact(content, findings);
    return { redacted, findings };
}
//# sourceMappingURL=scanner.js.map