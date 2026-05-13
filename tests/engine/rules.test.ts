import { test, describe } from "node:test";
import assert from "node:assert";
import assertStrict from "node:assert/strict";
import { NAMED_RULES, ENTROPY_RULES, CLEAN_ROOM_RULES } from "../../src/engine/rules.js";

describe("rules — NAMED_RULES (gitleaks)", () => {
    test("has at least 160 named rules", () => {
        assert.ok(NAMED_RULES.length >= 160, `Expected >=160 named rules, got ${NAMED_RULES.length}`);
    });

    test("every rule has a non-empty id", () => {
        for (const rule of NAMED_RULES) {
            assert.ok(rule.id.length > 0, "Rule id must not be empty");
        }
    });

    test("every rule has a non-empty description", () => {
        for (const rule of NAMED_RULES) {
            assert.ok(rule.description.length > 0, `Description missing for rule: ${rule.id}`);
        }
    });

    test("every rule has a compiled RegExp", () => {
        for (const rule of NAMED_RULES) {
            assert.ok(rule.regex instanceof RegExp, `Rule ${rule.id} must have a RegExp`);
        }
    });

    test("every rule regex can execute without error", () => {
        const testStr = "test AKIAIOSFODNN7EXAMPLE test";
        for (const rule of NAMED_RULES) {
            // Reset lastIndex before each test
            rule.regex.lastIndex = 0;
            // Should not throw
            rule.regex.exec(testStr);
        }
    });

    test("every rule has a keywords array", () => {
        for (const rule of NAMED_RULES) {
            assert.ok(Array.isArray(rule.keywords), `Rule ${rule.id} must have keywords array`);
        }
    });

    test("every named rule is unique by id", () => {
        const ids = NAMED_RULES.map((r) => r.id);
        const uniqueIds = new Set(ids);
        assert.strictEqual(ids.length, uniqueIds.size, "All rule ids must be unique");
    });
});

describe("rules — ENTROPY_RULES", () => {
    test("has exactly 3 entropy rules", () => {
        assert.strictEqual(ENTROPY_RULES.length, 3);
    });

    test("includes entropy-base64 rule", () => {
        const rule = ENTROPY_RULES.find((r) => r.id === "entropy-base64");
        assertStrict.ok(rule);
        assert.strictEqual(rule.entropy, 4.5);
    });

    test("includes entropy-hex rule", () => {
        const rule = ENTROPY_RULES.find((r) => r.id === "entropy-hex");
        assertStrict.ok(rule);
        assert.strictEqual(rule.entropy, 3.0);
    });

    test("includes entropy-alphanumeric rule", () => {
        const rule = ENTROPY_RULES.find((r) => r.id === "entropy-alphanumeric");
        assertStrict.ok(rule);
        assert.strictEqual(rule.entropy, 4.0);
    });

    test("all entropy rules have regex with capture group", () => {
        for (const rule of ENTROPY_RULES) {
            // Check regex has at least one capture group
            const regexStr = rule.regex.source;
            assert.ok(regexStr.includes("(") && regexStr.includes(")"),
                `Entropy rule ${rule.id} regex should have a capture group`);
        }
    });

    test("all entropy rules have entropy threshold", () => {
        for (const rule of ENTROPY_RULES) {
            assert.ok(rule.entropy !== undefined, `Entropy rule ${rule.id} must have entropy threshold`);
            assert.ok(typeof rule.entropy === "number");
            assert.ok(rule.entropy > 0);
        }
    });
});

describe("rules — CLEAN_ROOM_RULES", () => {
    test("has clean-room rules", () => {
        assert.ok(CLEAN_ROOM_RULES.length > 0, "Should have at least one clean-room rule");
    });

    test("includes Groq API key rule", () => {
        const rule = CLEAN_ROOM_RULES.find((r) => r.id === "groq-api-key");
        assertStrict.ok(rule);
    });

    test("includes DeepSeek API key rule", () => {
        const rule = CLEAN_ROOM_RULES.find((r) => r.id === "deepseek-api-key");
        assertStrict.ok(rule);
    });

    test("includes Replicate API token rule", () => {
        const rule = CLEAN_ROOM_RULES.find((r) => r.id === "replicate-api-token");
        assertStrict.ok(rule);
    });

    test("includes ElevenLabs API key rule", () => {
        const rule = CLEAN_ROOM_RULES.find((r) => r.id === "elevenlabs-api-key");
        assertStrict.ok(rule);
    });

    test("includes LangSmith API key rule", () => {
        const rule = CLEAN_ROOM_RULES.find((r) => r.id === "langsmith-api-key");
        assertStrict.ok(rule);
    });

    test("includes LangFuse API key rule", () => {
        const rule = CLEAN_ROOM_RULES.find((r) => r.id === "langfuse-api-key");
        assertStrict.ok(rule);
    });

    test("includes Supabase token rule", () => {
        const rule = CLEAN_ROOM_RULES.find((r) => r.id === "supabase-token");
        assertStrict.ok(rule);
    });

    test("includes Vercel token rule", () => {
        const rule = CLEAN_ROOM_RULES.find((r) => r.id === "vercel-token");
        assertStrict.ok(rule);
    });

    test("includes MongoDB connection string rule", () => {
        const rule = CLEAN_ROOM_RULES.find((r) => r.id === "mongodb-connection-string");
        assertStrict.ok(rule);
    });

    test("includes PostgreSQL connection string rule", () => {
        const rule = CLEAN_ROOM_RULES.find((r) => r.id === "postgresql-connection-string");
        assertStrict.ok(rule);
    });

    test("includes Redis connection string rule", () => {
        const rule = CLEAN_ROOM_RULES.find((r) => r.id === "redis-connection-string");
        assertStrict.ok(rule);
    });

    test("includes WandB API key rule", () => {
        const rule = CLEAN_ROOM_RULES.find((r) => r.id === "wandb-api-key");
        assertStrict.ok(rule);
    });

    test("all clean-room rules have non-empty id and regex", () => {
        for (const rule of CLEAN_ROOM_RULES) {
            assert.ok(rule.id.length > 0, "Clean-room rule must have id");
            assert.ok(rule.regex instanceof RegExp, `Rule ${rule.id} must have RegExp`);
        }
    });

    test("all clean-room rules are unique by id", () => {
        const ids = CLEAN_ROOM_RULES.map((r) => r.id);
        assert.strictEqual(new Set(ids).size, ids.length);
    });
});

describe("rules — combined totals", () => {
    test("total rules count is correct", () => {
        const total = NAMED_RULES.length + CLEAN_ROOM_RULES.length + ENTROPY_RULES.length;
        assert.ok(total >= 175, `Expected >=175 total rules, got ${total}`);
    });

    test("no duplicate ids across all rule sets", () => {
        const allIds = [
            ...NAMED_RULES.map((r) => r.id),
            ...CLEAN_ROOM_RULES.map((r) => r.id),
            ...ENTROPY_RULES.map((r) => r.id),
        ];
        assert.strictEqual(new Set(allIds).size, allIds.length);
    });
});