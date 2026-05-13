import { scanAndRedact } from "../engine/scanner.js";
import { writeAuditBatch } from "../engine/audit.js";
function extractMessageText(event) {
    if ("text" in event && typeof event.text === "string")
        return event.text;
    if ("content" in event && typeof event.content === "string")
        return event.content;
    if ("message" in event && event.message) {
        const msg = event.message;
        if (typeof msg.text === "string")
            return msg.text;
        if (typeof msg.content === "string")
            return msg.content;
    }
    return null;
}
export async function handleLayer2Message(input) {
    try {
        const event = input.event;
        const type = event.type;
        if (type !== "message.updated" && type !== "message.created")
            return;
        const text = extractMessageText(event);
        if (!text)
            return;
        const { findings } = scanAndRedact(text, "message");
        if (findings.length > 0) {
            const auditEntries = findings.map((f) => ({
                timestamp: new Date().toISOString(),
                source: "message",
                ruleId: f.ruleId,
                description: f.description,
                fingerprint: f.redacted.match(/:([a-f0-9]{8})\]/)?.[1] || "",
            }));
            writeAuditBatch(auditEntries);
        }
    }
    catch {
        // Degrade gracefully — never block message sending
    }
}
//# sourceMappingURL=layer2-message.js.map