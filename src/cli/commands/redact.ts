import { readFileSync, writeFileSync, copyFileSync, existsSync } from "node:fs";
import { scanAndRedact } from "../../engine/scanner.js";
import { writeAuditBatch } from "../../engine/audit.js";
import type { Finding } from "../../engine/types.js";

export async function cmdRedact(positional: string[]): Promise<void> {
    if (positional.length === 0) {
        console.error("Usage: sd redact <file>");
        process.exit(1);
    }

    const filePath = positional[0];

    if (!existsSync(filePath)) {
        console.error(`Error: File not found: ${filePath}`);
        process.exit(1);
    }

    try {
        const content = readFileSync(filePath, "utf8");
        const { redacted, findings } = scanAndRedact(content, "file");

        if (findings.length === 0) {
            console.log("No secrets found. File unchanged.");
            return;
        }

        const backupPath = filePath + ".backup";
        copyFileSync(filePath, backupPath);
        writeFileSync(filePath, redacted, "utf8");

        const auditEntries = findings.map((f: Finding) => ({
            timestamp: new Date().toISOString(),
            source: "file",
            ruleId: f.ruleId,
            description: f.description,
            fingerprint: f.redacted.match(/:([a-f0-9]{8})\]/)?.[1] || "",
        }));
        writeAuditBatch(auditEntries);

        console.log(`Redacted ${findings.length} secret(s) in ${filePath}`);
        console.log(`Backup saved to ${backupPath}`);
        for (const f of findings) {
            console.log(`  ${f.ruleId}: ${f.redacted}`);
        }
    } catch (err) {
        console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
    }
}
