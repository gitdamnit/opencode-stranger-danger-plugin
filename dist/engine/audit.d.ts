import type { AuditEntry } from "./types.js";
export declare function setAuditPath(path: string): void;
export declare function writeAudit(entry: AuditEntry): void;
export declare function writeAuditBatch(entries: AuditEntry[]): void;
export declare function readAuditLog(): string;
export declare function getAuditPath(): string;
//# sourceMappingURL=audit.d.ts.map