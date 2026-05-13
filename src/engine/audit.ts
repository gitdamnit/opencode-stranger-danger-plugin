import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import type { AuditEntry } from "./types.js";

const DEFAULT_AUDIT_PATH = ".opencode/state/strangerdanger-audit.jsonl";

let auditPath: string = DEFAULT_AUDIT_PATH;

export function setAuditPath(path: string): void {
    auditPath = path;
}

export function writeAudit(entry: AuditEntry): void {
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

export function writeAuditBatch(entries: AuditEntry[]): void {
    for (const entry of entries) {
        writeAudit(entry);
    }
}

export function readAuditLog(): string {
    if (!existsSync(auditPath)) return "";
    return readFileSync(auditPath, "utf8");
}

export function getAuditPath(): string {
    return auditPath;
}
