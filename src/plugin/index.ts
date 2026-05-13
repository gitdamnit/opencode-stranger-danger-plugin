import { type Plugin, tool } from "@opencode-ai/plugin";
import { z } from "zod";
import { scanAndRedact } from "../engine/scanner.js";
import { getAuditPath, readAuditLog } from "../engine/audit.js";
import { loadAllowlist, saveAllowlistEntry } from "../engine/allowlist.js";
import { NAMED_RULES, ENTROPY_RULES, CLEAN_ROOM_RULES } from "../engine/rules.js";
import { handleLayer1 } from "./layer1.js";
import { handleLayer2Compaction } from "./layer2-compaction.js";
import { handleLayer2Message } from "./layer2-message.js";
import { handleLayer3 } from "./layer3.js";
import type { Finding } from "../engine/types.js";

export const strangerDanger: Plugin = async (_ctx) => {
    const allRules = [...NAMED_RULES, ...CLEAN_ROOM_RULES, ...ENTROPY_RULES];

    return {
        "tool.execute.before": handleLayer1,
        "experimental.session.compacting": handleLayer2Compaction,
        event: handleLayer2Message,
        "tool.execute.after": handleLayer3,

        tool: {
            sd_status: tool({
                description: "Show strangerDanger status — rule count, findings this session, audit log path",
                args: {},
                async execute() {
                    const ruleCount = allRules.length;
                    const auditPath = getAuditPath();
                    let findingCount = 0;
                    try {
                        const log = readAuditLog();
                        findingCount = log.split("\n").filter((l) => l.trim()).length;
                    } catch {
                        // Audit log may not exist yet
                    }
                    return `strangerDanger v0.1.0\nRules: ${ruleCount}\nFindings this session: ${findingCount}\nAudit log: ${auditPath}`;
                },
            }),

            sd_audit: tool({
                description: "Show audit log for current session — all redactions made, with timestamps and rule IDs",
                args: {},
                async execute() {
                    try {
                        const log = readAuditLog();
                        if (!log.trim()) return "No audit entries yet.";
                        const lines = log.trim().split("\n");
                        const entries = lines.map((l) => {
                            try {
                                const entry = JSON.parse(l);
                                return `[${entry.timestamp}] ${entry.ruleId} — fingerprint: ${entry.fingerprint} — source: ${entry.source}`;
                            } catch {
                                return l;
                            }
                        });
                        return entries.join("\n");
                    } catch {
                        return "Audit log not found.";
                    }
                },
            }),

            sd_allowlist_add: tool({
                description: "Add an entry to the allowlist — by fingerprint, ruleId, path, or regex",
                args: {
                    description: z.string().optional(),
                    fingerprint: z.string().optional(),
                    ruleId: z.string().optional(),
                    path: z.string().optional(),
                    regex: z.string().optional(),
                },
                async execute(args) {
                    saveAllowlistEntry({
                        description: args.description,
                        fingerprint: args.fingerprint,
                        ruleId: args.ruleId,
                        path: args.path,
                        regex: args.regex,
                    });
                    return "Allowlist entry added.";
                },
            }),

            sd_allowlist_show: tool({
                description: "Show current allowlist entries",
                args: {},
                async execute() {
                    const allowlist = loadAllowlist();
                    if (allowlist.entries.length === 0) return "No allowlist entries.";
                    return allowlist.entries.map((e, i) =>
                        `${i + 1}. ${e.description || "(no description)"} | fingerprint: ${e.fingerprint || "—"} | ruleId: ${e.ruleId || "—"} | path: ${e.path || "—"} | regex: ${e.regex || "—"}`,
                    ).join("\n");
                },
            }),

            sd_scan: tool({
                description: "Manually scan a file or string against all rules — useful for testing",
                args: {
                    content: z.string(),
                    source: z.enum(["file", "context", "output", "message"]).optional(),
                },
                async execute(args) {
                    const src = args.source || "file";
                    const { findings } = scanAndRedact(args.content, src as Finding["source"]);
                    if (findings.length === 0) return "No secrets detected.";
                    return findings.map((f) =>
                        `${f.ruleId}: ${f.description}\n  Redacted: ${f.redacted}\n  Offset: ${f.offset}`,
                    ).join("\n\n");
                },
            }),
        },
    };
};

export default strangerDanger;
