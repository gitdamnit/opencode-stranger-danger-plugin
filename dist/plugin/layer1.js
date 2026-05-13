import { readFileSync } from "node:fs";
import { statSync } from "node:fs";
import { writeFileSync } from "node:fs";
import { scanAndRedact } from "../engine/scanner.js";
import { writeAuditBatch } from "../engine/audit.js";
const MAX_FILE_SIZE = 10 * 1024 * 1024;
function isBinary(content) {
    for (let i = 0; i < Math.min(content.length, 8192); i++) {
        if (content[i] === 0)
            return true;
    }
    return false;
}
function isSensitiveDotEnvPath(filePath) {
    const normalized = filePath.replace(/\\/g, "/");
    if (/(^|\/)\.env\.example$/.test(normalized))
        return false;
    return /(^|\/)\.env($|\.)/.test(normalized);
}
export async function handleLayer1(input, output) {
    const filePath = output.args?.filePath;
    if (!filePath)
        return;
    try {
        if (input.tool !== "read" && input.tool !== "edit" && input.tool !== "write") {
            return;
        }
        if (isSensitiveDotEnvPath(filePath))
            return;
        let stats;
        try {
            stats = statSync(filePath);
        }
        catch {
            return;
        }
        if (stats.size > MAX_FILE_SIZE)
            return;
        const raw = readFileSync(filePath);
        if (isBinary(raw))
            return;
        const content = raw.toString("utf8");
        const { redacted, findings } = scanAndRedact(content, "file", filePath);
        if (findings.length > 0) {
            const auditEntries = findings.map((f) => ({
                timestamp: new Date().toISOString(),
                source: "file",
                ruleId: f.ruleId,
                description: f.description,
                fingerprint: f.redacted.match(/:([a-f0-9]{8})\]/)?.[1] || "",
            }));
            writeAuditBatch(auditEntries);
            if (redacted !== content) {
                writeFileSync(filePath, redacted, "utf8");
            }
        }
    }
    catch {
        // Degrade gracefully — never block tool execution
    }
}
//# sourceMappingURL=layer1.js.map