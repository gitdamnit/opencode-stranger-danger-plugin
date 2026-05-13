import { scanAndRedact } from "../engine/scanner.js";
import { writeAuditBatch } from "../engine/audit.js";
import type { Finding } from "../engine/types.js";

export async function handleLayer2Compaction(
    _input: { sessionID: string },
    output: { context: string[]; prompt?: string },
): Promise<void> {
    try {
        if (!output.context || output.context.length === 0) return;

        const allFindings: Finding[] = [];

        for (let i = 0; i < output.context.length; i++) {
            const { redacted, findings } = scanAndRedact(output.context[i], "context");
            output.context[i] = redacted;
            allFindings.push(...findings);
        }

        if (allFindings.length > 0) {
            const auditEntries = allFindings.map((f) => ({
                timestamp: new Date().toISOString(),
                source: "context",
                ruleId: f.ruleId,
                description: f.description,
                fingerprint: f.redacted.match(/:([a-f0-9]{8})\]/)?.[1] || "",
            }));
            writeAuditBatch(auditEntries);
        }
    } catch {
        // Degrade gracefully — never block compaction
    }
}
