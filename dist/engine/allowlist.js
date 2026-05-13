import { existsSync, readFileSync, appendFileSync } from "node:fs";
/**
 * Normalize a path for comparison: resolve to lowercase, no leading ./
 * Supports glob-like patterns with * and **.
 */
function minipath(p) {
    return p.replace(/\\/g, "/").replace(/^\.\//, "").toLowerCase();
}
const DEFAULT_ALLOWLIST_PATH = ".strangerdanger-allowlist.toml";
function parseSimpleToml(content) {
    const entries = [];
    let current = {};
    for (const rawLine of content.split("\n")) {
        const line = rawLine.trim();
        if (!line || line.startsWith("#"))
            continue;
        if (line === "[[entries]]" || line === "[[allowlist]]") {
            if (Object.keys(current).length > 0) {
                entries.push(current);
            }
            current = {};
            continue;
        }
        const eqIdx = line.indexOf("=");
        if (eqIdx === -1)
            continue;
        const key = line.slice(0, eqIdx).trim();
        let value = line.slice(eqIdx + 1).trim();
        if ((value.startsWith('"') && value.endsWith('"')) ||
            (value.startsWith("'") && value.endsWith("'"))) {
            value = value.slice(1, -1);
        }
        current[key] = value;
    }
    if (Object.keys(current).length > 0) {
        entries.push(current);
    }
    return entries;
}
function serializeTomlEntry(entry) {
    const lines = ["[[entries]]"];
    if (entry.description)
        lines.push(`description = "${entry.description}"`);
    if (entry.fingerprint)
        lines.push(`fingerprint = "${entry.fingerprint}"`);
    if (entry.ruleId)
        lines.push(`ruleId = "${entry.ruleId}"`);
    if (entry.path)
        lines.push(`path = "${entry.path}"`);
    if (entry.regex)
        lines.push(`regex = "${entry.regex}"`);
    return lines.join("\n");
}
export function loadAllowlist(path) {
    const target = path || DEFAULT_ALLOWLIST_PATH;
    if (!existsSync(target)) {
        return { entries: [] };
    }
    try {
        const content = readFileSync(target, "utf8");
        return { entries: parseSimpleToml(content) };
    }
    catch {
        return { entries: [] };
    }
}
export function saveAllowlistEntry(entry, path) {
    const target = path || DEFAULT_ALLOWLIST_PATH;
    const block = serializeTomlEntry(entry) + "\n\n";
    appendFileSync(target, block, "utf8");
}
export function filterByAllowlist(findings, allowlist) {
    if (allowlist.entries.length === 0)
        return findings;
    return findings.filter((finding) => {
        for (const entry of allowlist.entries) {
            if (entry.fingerprint) {
                const fp = finding.redacted.match(/:([a-f0-9]{8})\]/);
                if (fp && fp[1] === entry.fingerprint)
                    return false;
            }
            if (entry.ruleId && finding.ruleId === entry.ruleId)
                return false;
            if (entry.path) {
                if (finding.source === "file" && finding.filePath &&
                    minipath(finding.filePath).includes(minipath(entry.path)))
                    return false;
            }
            if (entry.regex) {
                try {
                    const re = new RegExp(entry.regex);
                    if (re.test(finding.match))
                        return false;
                }
                catch {
                    // Invalid regex in allowlist, skip this entry
                }
            }
        }
        return true;
    });
}
//# sourceMappingURL=allowlist.js.map