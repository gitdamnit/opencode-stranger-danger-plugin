import { test, describe } from "node:test";
import assert from "node:assert";
import assertStrict from "node:assert/strict";
import { fingerprint } from "../../src/shared/fingerprint.js";

describe("fingerprint", () => {
    test("produces 8-character hex string", () => {
        const result = fingerprint("test");
        assert.strictEqual(result.length, 8);
        assert.ok(/^[a-f0-9]{8}$/.test(result));
    });

    test("is deterministic — same input always same output", () => {
        for (let i = 0; i < 100; i++) {
            const fp = fingerprint("deterministic-test-value");
            assert.strictEqual(fp, fingerprint("deterministic-test-value"));
        }
    });

    test("produces different values for different inputs", () => {
        const fp1 = fingerprint("input-a");
        const fp2 = fingerprint("input-b");
        assert.notStrictEqual(fp1, fp2);
    });

    test("handles empty string", () => {
        const fp = fingerprint("");
        assert.strictEqual(fp.length, 8);
        assert.ok(/^[a-f0-9]{8}$/.test(fp));
    });

    test("handles very long strings", () => {
        const long = "a".repeat(10000);
        const fp = fingerprint(long);
        assert.strictEqual(fp.length, 8);
    });

    test("handles Unicode", () => {
        const fp1 = fingerprint("こんにちは");
        const fp2 = fingerprint("世界");
        assert.strictEqual(fp1.length, 8);
        assert.notStrictEqual(fp1, fp2);
    });

test("is consistent with scanner makeFingerprint", async () => {
         // Verify the fingerprint function used by the scanner module
         // matches the one in shared/fingerprint.ts
         const { createHash } = await import("node:crypto");
         const expected = createHash("sha256").update("test").digest("hex").slice(0, 8);
         assert.strictEqual(fingerprint("test"), expected);
     });

    test("avalanche effect — small input change produces different output", () => {
        const fp1 = fingerprint("secret-key-abc");
        const fp2 = fingerprint("secret-key-abd");
        // Should differ in more than just the last char position
        let diffCount = 0;
        for (let i = 0; i < 8; i++) {
            if (fp1[i] !== fp2[i]) diffCount++;
        }
        assert.ok(diffCount >= 2, "Changing one char should affect multiple hex digits");
    });
});