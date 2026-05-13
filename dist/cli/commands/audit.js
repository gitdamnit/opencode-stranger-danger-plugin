import { readAuditLog, getAuditPath } from "../../engine/audit.js";
export async function cmdAudit() {
    const log = readAuditLog();
    if (!log.trim()) {
        console.log("No audit entries yet.");
        return;
    }
    const lines = log.trim().split("\n");
    console.log(`Audit log: ${getAuditPath()}`);
    console.log(`Entries: ${lines.length}`);
    console.log("");
    for (const line of lines) {
        try {
            const entry = JSON.parse(line);
            console.log(`[${entry.timestamp}] ${entry.ruleId} — ${entry.source} — fingerprint: ${entry.fingerprint}`);
        }
        catch {
            console.log(line);
        }
    }
}
//# sourceMappingURL=audit.js.map