import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
const DEFAULT_AUDIT_PATH = ".opencode/state/strangerdanger-audit.jsonl";
let auditPath = DEFAULT_AUDIT_PATH;
export function setAuditPath(path) {
    auditPath = path;
}
export function writeAudit(entry) {
    const dir = dirname(auditPath);
    if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
    }
    const line = JSON.stringify({
        ...entry,
        timestamp: entry.timestamp || new Date().toISOString(),
    });
    appendFileSync(auditPath, line + "\n", "utf8");
}
export function writeAuditBatch(entries) {
    for (const entry of entries) {
        writeAudit(entry);
    }
}
export function readAuditLog() {
    if (!existsSync(auditPath))
        return "";
    return readFileSync(auditPath, "utf8");
}
export function getAuditPath() {
    return auditPath;
}
//# sourceMappingURL=audit.js.map