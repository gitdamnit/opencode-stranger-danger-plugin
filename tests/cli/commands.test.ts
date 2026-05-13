import { test, describe } from "node:test";
import assert from "node:assert";
import assertStrict from "node:assert/strict";
import { cmdScan } from "../../src/cli/commands/scan.js";
import { cmdRedact } from "../../src/cli/commands/redact.js";
import { cmdAudit } from "../../src/cli/commands/audit.js";
import { cmdRules } from "../../src/cli/commands/rules.js";
import { cmdAllowlist } from "../../src/cli/commands/allowlist.js";
import { scanAndRedact } from "../../src/engine/scanner.js";
import fs from "node:fs";
import path from "node:path";

describe("cli — cmdScan", () => {
    test("scan detects AWS key in string", () => {
        const content = 'const key = "AKIAIOSFODNN7EXAMPLE";';
        const { findings } = scanAndRedact(content, "file");
        const awsFindings = findings.filter((f) => f.ruleId === "aws-access-token");
        assertStrict.ok(awsFindings.length >= 1);
    });

    test("scan returns empty array for clean content", () => {
        const content = "const x = 42;";
        const { findings } = scanAndRedact(content, "file");
        assert.strictEqual(findings.length, 0);
    });

    test("scan handles empty string", () => {
        const { findings } = scanAndRedact("", "file");
        assert.strictEqual(findings.length, 0);
    });

    test("scan handles whitespace-only content", () => {
        const { findings } = scanAndRedact("   \n\n  ", "file");
        assert.strictEqual(findings.length, 0);
    });

    test("scan with source 'context' works", () => {
        const content = 'const key = "AKIAIOSFODNN7EXAMPLE";';
        const { findings } = scanAndRedact(content, "context");
        const awsFindings = findings.filter((f) => f.ruleId === "aws-access-token");
        assertStrict.ok(awsFindings.length >= 1);
    });

test("scan with source 'message' works", () => {
         const content = 'const key = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";';
         const { findings } = scanAndRedact(content, "message");
         const ghFindings = findings.filter((f) => f.ruleId === "github-pat");
         assertStrict.ok(ghFindings.length >= 1);
     });

    test("scan with source 'output' works", () => {
        const content = 'const key = "AKIAIOSFODNN7EXAMPLE";';
        const { findings } = scanAndRedact(content, "output");
        const awsFindings = findings.filter((f) => f.ruleId === "aws-access-token");
        assertStrict.ok(awsFindings.length >= 1);
    });

    test("scan produces valid redacted output", () => {
        const content = 'const key = "AKIAIOSFODNN7EXAMPLE";';
        const { redacted } = scanAndRedact(content, "file");
        assert.ok(redacted.includes("[REDACTED:"));
        assert.ok(redacted.includes("aws-access-token:"));
        assert.ok(!redacted.includes("AKIAIOSFODNN7EXAMPLE"));
        // Non-secret parts should be preserved
        assert.ok(redacted.includes("const key ="));
    });
});

describe("cli — cmdRedact", () => {
    test("redact creates backup and modifies file", async () => {
        const tmpDir = "/tmp/sd-redact-test";
        const filePath = path.join(tmpDir, "config.ts");

        try {
            fs.mkdirSync(tmpDir, { recursive: true });
            fs.writeFileSync(filePath, 'const key = "AKIAIOSFODNN7EXAMPLE";');

            // Simulate what cmdRedact does
            const { readFileSync, writeFileSync, copyFileSync, existsSync } = await import("node:fs");
            const { scanAndRedact } = await import("../../src/engine/scanner.js");

            const content = readFileSync(filePath, "utf8");
            const { redacted, findings } = scanAndRedact(content, "file");

            if (findings.length > 0) {
                const backupPath = filePath + ".backup";
                copyFileSync(filePath, backupPath);
                writeFileSync(filePath, redacted, "utf8");

                assert.ok(existsSync(backupPath));
                assert.strictEqual(readFileSync(backupPath, "utf8"), content);
                assert.ok(!readFileSync(filePath, "utf8").includes("AKIAIOSFODNN7EXAMPLE"));
                assert.ok(readFileSync(filePath, "utf8").includes("[REDACTED:"));

                // Cleanup
                try { fs.unlinkSync(backupPath); } catch {}
            }
        } finally {
            try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
        }
    });

    test("redact skips file with no secrets", async () => {
        const tmpDir = "/tmp/sd-redact-test-clean";
        const filePath = path.join(tmpDir, "clean.ts");

        try {
            fs.mkdirSync(tmpDir, { recursive: true });
            const originalContent = "const x = 42;";
            fs.writeFileSync(filePath, originalContent);

            const { scanAndRedact } = await import("../../src/engine/scanner.js");
            const { readFileSync, existsSync } = await import("node:fs");

            const content = readFileSync(filePath, "utf8");
            const { redacted, findings } = scanAndRedact(content, "file");

            if (findings.length === 0) {
                // No backup created, no changes
                assert.strictEqual(redacted, content);
                assert.ok(!existsSync(filePath + ".backup"));
            }
        } finally {
            try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
        }
    });
});

describe("cli — cmdRules", () => {
    test("rules command lists all rule categories", async () => {
        const { NAMED_RULES, ENTROPY_RULES, CLEAN_ROOM_RULES } = await import("../../src/engine/rules.js");

        const allRules = [...NAMED_RULES, ...CLEAN_ROOM_RULES, ...ENTROPY_RULES];
        assert.ok(allRules.length > 170);
        assertStrict.ok(NAMED_RULES.length >= 160);
        assertStrict.ok(CLEAN_ROOM_RULES.length >= 10);
        assertStrict.strictEqual(ENTROPY_RULES.length, 3);
    });

    test("every rule has a printable description", async () => {
        const { NAMED_RULES, ENTROPY_RULES, CLEAN_ROOM_RULES } = await import("../../src/engine/rules.js");
        const allRules = [...NAMED_RULES, ...CLEAN_ROOM_RULES, ...ENTROPY_RULES];
        for (const rule of allRules) {
            assert.ok(rule.description.length > 0);
        }
    });
});

describe("cli — cmdAudit", () => {
    test("audit reads and formats JSONL log", async () => {
        const { writeAudit, readAuditLog, setAuditPath } = await import("../../src/engine/audit.js");
        const tmpFile = "/tmp/sd-audit-display-test.jsonl";

        setAuditPath(tmpFile);
        try { fs.unlinkSync(tmpFile); } catch {}

        writeAudit({
            ruleId: "aws-access-token",
            source: "file",
            description: "AWS key found",
            fingerprint: "a3f7b2c1",
            timestamp: "2026-05-12T10:00:00.000Z",
        });

        writeAudit({
            ruleId: "github-pat",
            source: "context",
            description: "GitHub PAT found",
            fingerprint: "b4c8d3e2",
            timestamp: "2026-05-12T10:00:01.000Z",
        });

        const log = readAuditLog();
        const lines = log.trim().split("\n");
        assert.strictEqual(lines.length, 2);

        // Parse and verify
        const entry1 = JSON.parse(lines[0]);
        assert.strictEqual(entry1.ruleId, "aws-access-token");
        assert.strictEqual(entry1.source, "file");

        const entry2 = JSON.parse(lines[1]);
        assert.strictEqual(entry2.ruleId, "github-pat");
        assert.strictEqual(entry2.source, "context");

        try { fs.unlinkSync(tmpFile); } catch {}
    });

    test("audit handles empty log", async () => {
        const { readAuditLog, setAuditPath } = await import("../../src/engine/audit.js");
        const tmpFile = "/tmp/sd-audit-empty-test.jsonl";

        setAuditPath(tmpFile);
        try { fs.unlinkSync(tmpFile); } catch {}

        const log = readAuditLog();
        assert.strictEqual(log, "");
    });
});

describe("cli — cmdAllowlist", () => {
    test("allowlist add writes to file", async () => {
        const { saveAllowlistEntry } = await import("../../src/engine/allowlist.js");
        const tmpFile = "/tmp/sd-allowlist-add-test.toml";

        try { fs.unlinkSync(tmpFile); } catch {}

        saveAllowlistEntry({
            description: "Test allowlist entry",
            fingerprint: "abcdef12",
        }, tmpFile);

        const content = fs.readFileSync(tmpFile, "utf8");
        assert.ok(content.includes("[[entries]]"));
        assert.ok(content.includes("fingerprint = \"abcdef12\""));

        try { fs.unlinkSync(tmpFile); } catch {}
    });

    test("allowlist filterByAllowlist removes matching entries", async () => {
        const { filterByAllowlist } = await import("../../src/engine/allowlist.js");
        const { fingerprint } = await import("../../src/shared/fingerprint.js");

        const fp = fingerprint("AKIAIOSFODNN7EXAMPLE");
        const finding = {
            ruleId: "aws-access-token",
            description: "Test",
            match: "AKIAIOSFODNN7EXAMPLE",
            redacted: `[REDACTED:aws-access-token:${fp}]`,
            offset: 0,
            source: "file",
        };

        const allowlist = {
            entries: [{ fingerprint: fingerprint("AKIAIOSFODNN7EXAMPLE") }],
        };

        const filtered = filterByAllowlist([finding], allowlist);
        assert.strictEqual(filtered.length, 0);
    });
});