import { test, describe } from "node:test";
import assert from "node:assert";
import assertStrict from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { filterByAllowlist, loadAllowlist, saveAllowlistEntry } from "../../src/engine/allowlist.js";
import { fingerprint } from "../../src/shared/fingerprint.js";
import type { Finding, Allowlist } from "../../src/engine/types.js";

function makeFinding(ruleId: string, match: string, filePath?: string): Finding {
    const fp = fingerprint(match);
    return {
        ruleId,
        description: `Test ${ruleId}`,
        match,
        redacted: `[REDACTED:${ruleId}:${fp}]`,
        offset: 0,
        source: "file",
        ...(filePath ? { filePath } : {}),
    };
}

describe("allowlist — filterByAllowlist", () => {
    test("empty allowlist passes all findings through", () => {
        const findings = [makeFinding("aws-access-token", "AKIA123")];
        const allowlist: Allowlist = { entries: [] };
        const filtered = filterByAllowlist(findings, allowlist);
        assert.strictEqual(filtered.length, 1);
    });

    test("allowlist by fingerprint filters matching finding", () => {
        const finding = makeFinding("aws-access-token", "AKIA123");
        const fp = fingerprint("AKIA123");
        const allowlist: Allowlist = { entries: [{ fingerprint: fp }] };
        const filtered = filterByAllowlist([finding], allowlist);
        assert.strictEqual(filtered.length, 0);
    });

    test("allowlist by fingerprint does not filter non-matching finding", () => {
        const finding = makeFinding("aws-access-token", "AKIA999");
        const fp = fingerprint("AKIA123");
        const allowlist: Allowlist = { entries: [{ fingerprint: fp }] };
        const filtered = filterByAllowlist([finding], allowlist);
        assert.strictEqual(filtered.length, 1);
    });

    test("allowlist by ruleId filters matching finding", () => {
        const finding = makeFinding("aws-access-token", "AKIA123");
        const allowlist: Allowlist = { entries: [{ ruleId: "aws-access-token" }] };
        const filtered = filterByAllowlist([finding], allowlist);
        assert.strictEqual(filtered.length, 0);
    });

    test("allowlist by ruleId does not filter non-matching finding", () => {
        const finding = makeFinding("aws-access-token", "AKIA123");
        const allowlist: Allowlist = { entries: [{ ruleId: "github-pat" }] };
        const filtered = filterByAllowlist([finding], allowlist);
        assert.strictEqual(filtered.length, 1);
    });

    test("allowlist by regex filters matching finding", () => {
        const finding = makeFinding("aws-access-token", "AKIA123");
        const allowlist: Allowlist = { entries: [{ regex: "AKIA.*" }] };
        const filtered = filterByAllowlist([finding], allowlist);
        assert.strictEqual(filtered.length, 0);
    });

    test("allowlist by regex does not filter non-matching finding", () => {
        const finding = makeFinding("aws-access-token", "AKIA123");
        const allowlist: Allowlist = { entries: [{ regex: "GHOP_.*" }] };
        const filtered = filterByAllowlist([finding], allowlist);
        assert.strictEqual(filtered.length, 1);
    });

    test("invalid regex in allowlist is handled gracefully", () => {
        const finding = makeFinding("aws-access-token", "AKIA123");
        const allowlist: Allowlist = { entries: [{ regex: "[invalid" }] };
        const filtered = filterByAllowlist([finding], allowlist);
        // Invalid regex should not filter — finding passes through
        assert.strictEqual(filtered.length, 1);
    });

    test("multiple allowlist entries — any match filters", () => {
        const finding1 = makeFinding("aws-access-token", "AKIA123");
        const finding2 = makeFinding("github-pat", "ghp_ABC");
        const allowlist: Allowlist = {
            entries: [
                { ruleId: "aws-access-token" },
                { fingerprint: fingerprint("ghp_ABC") },
            ],
        };
        const filtered = filterByAllowlist([finding1, finding2], allowlist);
        assert.strictEqual(filtered.length, 0);
    });

    test("fingerprint match takes priority when multiple entries exist", () => {
        const finding = makeFinding("aws-access-token", "AKIA123");
        const fp = fingerprint("AKIA123");
        const allowlist: Allowlist = {
            entries: [
                { ruleId: "github-pat" },        // doesn't match
                { fingerprint: fp },             // does match
            ],
        };
        const filtered = filterByAllowlist([finding], allowlist);
        assert.strictEqual(filtered.length, 0);
    });

    test("finding without filePath cannot match path-based allowlist", () => {
        const finding = makeFinding("aws-access-token", "AKIA123");
        const allowlist: Allowlist = { entries: [{ path: "test/" }] };
        const filtered = filterByAllowlist([finding], allowlist);
        assert.strictEqual(filtered.length, 1);
    });

    test("finding with matching filePath is filtered by path allowlist", () => {
        const finding = makeFinding("aws-access-token", "AKIA123", "test/fixtures/secrets.ts");
        const allowlist: Allowlist = { entries: [{ path: "test/" }] };
        const filtered = filterByAllowlist([finding], allowlist);
        assert.strictEqual(filtered.length, 0);
    });

    test("finding with non-matching filePath is not filtered by path allowlist", () => {
        const finding = makeFinding("aws-access-token", "AKIA123", "src/config.ts");
        const allowlist: Allowlist = { entries: [{ path: "test/" }] };
        const filtered = filterByAllowlist([finding], allowlist);
        assert.strictEqual(filtered.length, 1);
    });

    test("source 'context' prevents path-based allowlist matching", () => {
        const finding: Finding = {
            ruleId: "aws-access-token",
            description: "test",
            match: "AKIA123",
            redacted: "[REDACTED:aws-access-token:abc12345]",
            offset: 0,
            source: "context",
        };
        const allowlist: Allowlist = { entries: [{ path: "test/" }] };
        const filtered = filterByAllowlist([finding], allowlist);
        assert.strictEqual(filtered.length, 1);
    });
});

describe("allowlist — loadAllowlist", () => {
    test("returns empty entries when file does not exist", () => {
        const allowlist = loadAllowlist(".nonexistent-file.toml");
        assert.ok(Array.isArray(allowlist.entries));
        assert.strictEqual(allowlist.entries.length, 0);
    });

    test("parses TOML with fingerprint entries", () => {
        const tmpFile = "/tmp/test-allowlist.toml";
        const content = `
[[entries]]
description = "Known test key"
fingerprint = "a3f7b2c1"
`;
        fs.writeFileSync(tmpFile, content);
        try {
            const allowlist = loadAllowlist(tmpFile);
            assert.strictEqual(allowlist.entries.length, 1);
            assert.strictEqual(allowlist.entries[0].fingerprint, "a3f7b2c1");
            assert.strictEqual(allowlist.entries[0].description, "Known test key");
        } finally {
            try { fs.unlinkSync(tmpFile); } catch {}
        }
    });

    test("parses TOML with ruleId entries", () => {
        const tmpFile = "/tmp/test-allowlist2.toml";
        const content = `
[[entries]]
description = "Ignore AWS keys in infra"
ruleId = "aws-access-token"
`;
        fs.writeFileSync(tmpFile, content);
        try {
            const allowlist = loadAllowlist(tmpFile);
            assert.strictEqual(allowlist.entries.length, 1);
            assert.strictEqual(allowlist.entries[0].ruleId, "aws-access-token");
        } finally {
            try { fs.unlinkSync(tmpFile); } catch {}
        }
    });

    test("parses TOML with path entries", () => {
        const tmpFile = "/tmp/test-allowlist3.toml";
        const content = `
[[entries]]
description = "Test fixtures"
path = "test/fixtures/*.ts"
`;
        fs.writeFileSync(tmpFile, content);
        try {
            const allowlist = loadAllowlist(tmpFile);
            assert.strictEqual(allowlist.entries.length, 1);
            assert.strictEqual(allowlist.entries[0].path, "test/fixtures/*.ts");
        } finally {
            try { fs.unlinkSync(tmpFile); } catch {}
        }
    });

    test("parses TOML with regex entries", () => {
        const tmpFile = "/tmp/test-allowlist4.toml";
        const content = `
[[entries]]
description = "Example values"
regex = "EXAMPLE"
`;
        fs.writeFileSync(tmpFile, content);
        try {
            const allowlist = loadAllowlist(tmpFile);
            assert.strictEqual(allowlist.entries.length, 1);
            assert.strictEqual(allowlist.entries[0].regex, "EXAMPLE");
        } finally {
            try { fs.unlinkSync(tmpFile); } catch {}
        }
    });

    test("parses multiple entries", () => {
        const tmpFile = "/tmp/test-allowlist5.toml";
        const content = `
[[entries]]
description = "Test key 1"
fingerprint = "aaa11111"

[[entries]]
description = "Test key 2"
ruleId = "github-pat"
`;
        fs.writeFileSync(tmpFile, content);
        try {
            const allowlist = loadAllowlist(tmpFile);
            assert.strictEqual(allowlist.entries.length, 2);
        } finally {
            try { fs.unlinkSync(tmpFile); } catch {}
        }
    });

    test("handles quoted values in TOML", () => {
        const tmpFile = "/tmp/test-allowlist6.toml";
        const content = `[[entries]]
description = "Entry with spaces"
fingerprint = "abcdef12"
`;
        fs.writeFileSync(tmpFile, content);
        try {
            const allowlist = loadAllowlist(tmpFile);
            assert.strictEqual(allowlist.entries.length, 1);
            assert.strictEqual(allowlist.entries[0].description, "Entry with spaces");
        } finally {
            try { fs.unlinkSync(tmpFile); } catch {}
        }
    });

    test("ignores comment lines", () => {
        const tmpFile = "/tmp/test-allowlist7.toml";
        const content = `
# This is a comment
[[entries]]
# inline comment
description = "Test"
fingerprint = "ff00aa11"
`;
        fs.writeFileSync(tmpFile, content);
        try {
            const allowlist = loadAllowlist(tmpFile);
            assert.strictEqual(allowlist.entries.length, 1);
        } finally {
            try { fs.unlinkSync(tmpFile); } catch {}
        }
    });
});

describe("allowlist — saveAllowlistEntry", () => {
    test("writes a new entry to file", () => {
        const tmpFile = "/tmp/test-save-allowlist.toml";
        try { fs.unlinkSync(tmpFile); } catch {}

        saveAllowlistEntry({ description: "Test entry", fingerprint: "abcdef12" }, tmpFile);

        const content = fs.readFileSync(tmpFile, "utf8");
        assert.ok(content.includes("[[entries]]"));
        assert.ok(content.includes('description = "Test entry"'));
        assert.ok(content.includes('fingerprint = "abcdef12"'));

        try { fs.unlinkSync(tmpFile); } catch {}
    });

    test("appends to existing file", () => {
        const tmpFile = "/tmp/test-save-allowlist2.toml";
        try { fs.unlinkSync(tmpFile); } catch {}

        saveAllowlistEntry({ description: "First", ruleId: "aws-access-token" }, tmpFile);
        saveAllowlistEntry({ description: "Second", fingerprint: "aabbccdd" }, tmpFile);

        const content = fs.readFileSync(tmpFile, "utf8");
        const entries = content.split("[[entries]]").length - 1;
        assert.strictEqual(entries, 2);

        try { fs.unlinkSync(tmpFile); } catch {}
    });

    test("writes all entry types", () => {
        const tmpFile = "/tmp/test-save-allowlist3.toml";
        try { fs.unlinkSync(tmpFile); } catch {}

        saveAllowlistEntry({
            description: "Full entry",
            fingerprint: "abcdef12",
            ruleId: "aws-access-token",
            path: "test/fixtures/*",
            regex: "EXAMPLE",
        }, tmpFile);

        const content = fs.readFileSync(tmpFile, "utf8");
        assert.ok(content.includes("fingerprint"));
        assert.ok(content.includes("ruleId"));
        assert.ok(content.includes("path"));
        assert.ok(content.includes("regex"));

        try { fs.unlinkSync(tmpFile); } catch {}
    });
});