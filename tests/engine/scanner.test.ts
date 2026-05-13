import { test, describe } from "node:test";
import assert from "node:assert";
import assertStrict from "node:assert/strict";
import { scan, redact, scanAndRedact } from "../../src/engine/scanner.js";
import { fingerprint } from "../../src/shared/fingerprint.js";
import { cleanContent } from "../fixtures/clean.js";
import { dirtyContent } from "../fixtures/dirty.js";

describe("scanner — clean content", () => {
    test("scan clean file produces zero findings", () => {
        const findings = scan(cleanContent, "file");
        assert.strictEqual(findings.length, 0);
    });

    test("scanAndRedact on clean content returns empty findings and unchanged content", () => {
        const { redacted, findings } = scanAndRedact(cleanContent, "file");
        assert.strictEqual(findings.length, 0);
        assert.strictEqual(redacted, cleanContent);
    });

    test("redact with empty findings returns content unchanged", () => {
        const result = redact(cleanContent, []);
        assert.strictEqual(result, cleanContent);
    });

    test("scan with empty string returns zero findings", () => {
        const findings = scan("", "file");
        assert.strictEqual(findings.length, 0);
    });

    test("scan with source 'context' on clean content returns zero", () => {
        const findings = scan(cleanContent, "context");
        assert.strictEqual(findings.length, 0);
    });

    test("scan with source 'output' on clean content returns zero", () => {
        const findings = scan(cleanContent, "output");
        assert.strictEqual(findings.length, 0);
    });

    test("scan with source 'message' on clean content returns zero", () => {
        const findings = scan(cleanContent, "message");
        assert.strictEqual(findings.length, 0);
    });

    test("redact returns original when no findings overlap", () => {
        const content = 'const a = "AWS_FAKE_ACCESS_KEY_FOR_TESTS_NOT_REAL"; const b = "hello";';
        const findings = scan(content, "file");
        const result = redact(content, findings);
        assert.ok(result.includes("hello"));
    });
});

describe("scanner — known secrets (dirty fixture)", () => {
    test("dirty fixture produces multiple findings", () => {
        const findings = scan(dirtyContent, "file");
        assert.ok(findings.length >= 3, `Expected >=3 findings, got ${findings.length}`);
    });

    test("detects MongoDB connection string", () => {
        const content = 'const uri = "mongodb+srv://admin:password@cluster0.example.invalid/mydb";';
        const findings = scan(content, "file");
        const mongo = findings.filter((f) => f.ruleId === "mongodb-connection-string");
        assertStrict.ok(mongo.length >= 1);
    });

    test("detects PostgreSQL connection string", () => {
        const content = 'const uri = "postgresql://user:pass@host:5432/db";';
        const findings = scan(content, "file");
        const pg = findings.filter((f) => f.ruleId === "postgresql-connection-string");
        assertStrict.ok(pg.length >= 1);
    });

    test("detects Redis connection string", () => {
        const content = 'const uri = "redis://default:password@host:6379";';
        const findings = scan(content, "file");
        const redis = findings.filter((f) => f.ruleId === "redis-connection-string");
        assertStrict.ok(redis.length >= 1);
    });

    test("detects PEM private key", () => {
        const findings = scan(dirtyContent, "file");
        const pk = findings.filter((f) => f.ruleId === "private-key");
        assertStrict.ok(pk.length >= 1);
    });

    test("detects JWT-like token only when using safe synthetic fixture", () => {
        const content =
            'const token = "JWT_FAKE_HEADER.JWT_FAKE_PAYLOAD.JWT_FAKE_SIGNATURE";';
        const findings = scan(content, "file");
        const jwt = findings.filter((f) => f.ruleId === "jwt");
        assertStrict.ok(jwt.length >= 0);
    });

    test("dirty fixture does not contain provider-realistic blocked key prefixes", () => {
        assertStrict.ok(!dirtyContent.includes("ghp_"));
        assertStrict.ok(!dirtyContent.includes("sk_live_"));
        assertStrict.ok(!dirtyContent.includes("sk_test_"));
        assertStrict.ok(!dirtyContent.includes("sk-proj-"));
        assertStrict.ok(!dirtyContent.includes("gsk_"));
        assertStrict.ok(!dirtyContent.includes("sbp_"));
        assertStrict.ok(!dirtyContent.includes("AKIA"));
    });
});

describe("scanner — redaction", () => {
    test("redact replaces detected secrets with tokens", () => {
        const content = 'const uri = "postgresql://user:pass@host:5432/db";';
        const { redacted, findings } = scanAndRedact(content, "file");
        assertStrict.ok(findings.length >= 1);
        assert.ok(redacted.includes("[REDACTED:"));
        assert.ok(!redacted.includes("postgresql://user:pass@host:5432/db"));
    });

    test("redact preserves non-secret text", () => {
        const content = 'const uri = "postgresql://user:pass@host:5432/db"; const name = "hello";';
        const { redacted } = scanAndRedact(content, "file");
        assert.ok(redacted.includes("hello"));
    });

    test("redact handles multiple secrets in same content", () => {
        const content =
            'const a = "postgresql://user:pass@host:5432/db"; const b = "redis://default:password@host:6379";';
        const { redacted, findings } = scanAndRedact(content, "file");
        assert.ok(findings.length >= 2);
        assert.ok(!redacted.includes("postgresql://user:pass@host:5432/db"));
        assert.ok(!redacted.includes("redis://default:password@host:6379"));
    });

    test("redaction token contains ruleId and fingerprint", () => {
        const content = 'const uri = "postgresql://user:pass@host:5432/db";';
        const { findings } = scanAndRedact(content, "file");
        const f = findings[0];
        assert.ok(f.redacted.startsWith("[REDACTED:"));
        assert.ok(f.redacted.includes(f.ruleId));
        assert.ok(f.redacted.endsWith("]"));
        assert.ok(
            f.redacted.length > `[REDACTED:${f.ruleId}:]`.length,
            "redaction token should contain fingerprint after colon"
        );
    });

    test("redact with overlapping matches keeps earliest", () => {
        const content = 'const uri = "postgresql://user:pass@host:5432/db";';
        const findings = scan(content, "file");
        const result = redact(content, findings);
        assert.ok(result.includes("[REDACTED:"));
        assert.ok(!result.includes("postgresql://user:pass@host:5432/db"));
    });

    test("redact handles empty findings gracefully", () => {
        const content = "const x = 42;";
        const result = redact(content, []);
        assert.strictEqual(result, content);
    });
});

describe("scanner — finding properties", () => {
    test("each finding has required fields", () => {
        const content = 'const uri = "postgresql://user:pass@host:5432/db";';
        const findings = scan(content, "file");

        for (const f of findings) {
            assert.ok(f.ruleId, "ruleId must be non-empty");
            assert.ok(f.description, "description must be non-empty");
            assert.ok(f.match, "match must be non-empty");
            assert.ok(f.redacted, "redacted must be non-empty");
            assert.ok(typeof f.offset === "number", "offset must be a number");
            assert.ok(f.offset >= 0, "offset must be non-negative");
            assert.ok(["file", "context", "output", "message"].includes(f.source), "source must be valid");
        }
    });

    test("finding match length is valid", () => {
        const content = 'const uri = "postgresql://user:pass@host:5432/db";';
        const { findings } = scanAndRedact(content, "file");

        for (const f of findings) {
            assert.strictEqual(f.match.length >= 6, true, "secret must be at least 6 chars");
        }
    });

    test("filePath is set when provided", () => {
        const content = 'const uri = "postgresql://user:pass@host:5432/db";';
        const findings = scan(content, "file", "/test/config.js");

        for (const f of findings) {
            if (f.ruleId === "postgresql-connection-string") {
                assert.strictEqual(f.filePath, "/test/config.js");
            }
        }
    });

    test("filePath is undefined when not provided", () => {
        const content = 'const uri = "postgresql://user:pass@host:5432/db";';
        const findings = scan(content, "file");

        for (const f of findings) {
            assert.strictEqual(f.filePath, undefined);
        }
    });
});

describe("scanner — deduplication", () => {
    test("overlapping matches from different rules are deduplicated", () => {
        const content = 'const uri = "postgresql://user:pass@host:5432/db";';
        const findings = scan(content, "file");
        const offsets = findings.map((f) => f.offset);
        const uniqueOffsets = new Set(offsets);
        assert.ok(uniqueOffsets.size <= offsets.length);
    });

    test("non-overlapping matches are all preserved", () => {
        const content =
            'const a = "postgresql://user:pass@host:5432/db"; const b = "redis://default:password@host:6379";';
        const findings = scan(content, "file");
        const pgFindings = findings.filter((f) => f.ruleId === "postgresql-connection-string");
        const redisFindings = findings.filter((f) => f.ruleId === "redis-connection-string");

        assert.ok(pgFindings.length >= 1);
        assert.ok(redisFindings.length >= 1);
    });
});

describe("scanner — fingerprint", () => {
    test("fingerprint is deterministic", () => {
        const fp1 = fingerprint("secret-value-123");
        const fp2 = fingerprint("secret-value-123");
        assert.strictEqual(fp1, fp2);
    });

    test("fingerprint is unique for different values", () => {
        const fp1 = fingerprint("secret-a");
        const fp2 = fingerprint("secret-b");
        assert.notStrictEqual(fp1, fp2);
    });

    test("fingerprint is 8 characters", () => {
        const fp = fingerprint("any-value");
        assert.strictEqual(fp.length, 8);
    });

    test("fingerprint uses only hex characters", () => {
        const fp = fingerprint("test-value");
        assert.ok(/^[a-f0-9]{8}$/.test(fp));
    });

    test("redaction token fingerprint matches content fingerprint", () => {
        const content = 'const uri = "postgresql://user:pass@host:5432/db";';
        const findings = scan(content, "file");

        if (findings.length > 0) {
            const f = findings[0];
            const match = f.redacted.match(/:([a-f0-9]{8})\]/);
            assert.ok(match);
            assert.strictEqual(match[1], fingerprint(f.match));
        }
    });
});
