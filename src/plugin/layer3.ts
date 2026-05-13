import { scanAndRedact } from "../engine/scanner.js";
import { writeAuditBatch } from "../engine/audit.js";
import type { Finding } from "../engine/types.js";

const MAX_OUTPUT_SIZE = 1024 * 1024;

export async function handleLayer3(
    _input: { tool: string; sessionID: string; callID: string; args: any },
    output: { title: string; output: string; metadata: any },
): Promise<void> {
    try {
        const text = output.output;
        if (!text) return;

        const scanText = text.length > MAX_OUTPUT_SIZE ? text.slice(0, MAX_OUTPUT_SIZE) : text;
        const { redacted, findings } = scanAndRedact(scanText, "output");

        if (findings.length > 0) {
            const auditEntries = findings.map((f: Finding) => ({
                timestamp: new Date().toISOString(),
                source: "output",
                ruleId: f.ruleId,
                description: f.description,
                fingerprint: f.redacted.match(/:([a-f0-9]{8})\]/)?.[1] || "",
            }));
            writeAuditBatch(auditEntries);

            output.output = redacted;
        }
    } catch {
        // Degrade gracefully — never block tool execution
    }
}
