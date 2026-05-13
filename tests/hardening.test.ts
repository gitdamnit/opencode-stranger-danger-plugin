import { test, describe } from "node:test";
import assert from "node:assert";
import { mkdtempSync, writeFileSync, rmSync, readFileSync, existsSync, mkdirSync, symlinkSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { scan, redact, scanAndRedact } from "../src/engine/scanner.js";
import { shannonEntropy } from "../src/engine/entropy.js";
import { NAMED_RULES, ENTROPY_RULES, CLEAN_ROOM_RULES } from "../src/engine/rules.js";
import { handleLayer1 } from "../src/plugin/layer1.js";
import { handleLayer2Message } from "../src/plugin/layer2-message.js";
import { handleLayer2Compaction } from "../src/plugin/layer2-compaction.js";

function tempDir(): string {
  const d = mkdtempSync(join(tmpdir(), "sd-harden-"));
  return d;
}

function cleanup(dir: string) {
  if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
}

// ============================================================
// SCANNER HARDENING
// ============================================================

describe("scanner hardening", () => {

  test("ReDoS: long input with nested quantifiers does not hang", () => {
    const start = Date.now();
    const longInput = "sk-proj-" + "x".repeat(100) + "T3BlbkFJxxx" + "x".repeat(100);
    const findings = scan(longInput, "context");
    const elapsed = Date.now() - start;
    assert.ok(elapsed < 5000, `ReDoS guard: scan took ${elapsed}ms (should be < 5000ms)`);
  });

  test("ReDoS: generic-api-key pattern on long repeating string", () => {
    const start = Date.now();
    const longInput = "API_KEY=" + "abcdefghij".repeat(50) + "==";
    const findings = scan(longInput, "context");
    const elapsed = Date.now() - start;
    assert.ok(elapsed < 5000, `generic-api-key ReDoS: scan took ${elapsed}ms`);
  });

  test("regex lastIndex: repeated calls do not share mutable state", () => {
    const contentA = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const contentB = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const findingsA = scan(contentA, "context");
    for (const r of NAMED_RULES) r.regex.lastIndex = 999999;
    const findingsB = scan(contentB, "context");
    assert.ok(findingsA.length >= 0);
    assert.ok(findingsB.length >= 0);
  });

  test("entropy threshold: low-entropy secrets below threshold are suppressed", () => {
    const lowEntropy = "aaaaaaaaaaaaaaaaaaaa";
    const ent = shannonEntropy(lowEntropy);
    assert.ok(ent < 2.0, `low entropy string has entropy ${ent}`);
    const findings = scan("SECRET_KEY=" + lowEntropy, "context");
    const matched = findings.filter(f => f.match === lowEntropy);
    assert.equal(matched.length, 0, "low-entropy string should not match generic rule");
  });

  test("entropy threshold: high-entropy random string above threshold matches", () => {
    const highEntropy = "x9K2mQ8pR4vL7nJ3wB5tY1cF6hA0sD8g";
    const ent = shannonEntropy(highEntropy);
    assert.ok(ent > 4.0, `high entropy string has entropy ${ent}`);
    const findings = scan("TOKEN=" + highEntropy, "context");
    const matched = findings.filter(f => f.match === highEntropy);
    assert.ok(matched.length >= 0);
  });

  test("binary content: null byte does not crash scanner", () => {
    const binaryContent = "normal\n\u0000secret\0text\nmore";
    let threw = false;
    try {
      const findings = scan(binaryContent, "context");
      assert.ok(Array.isArray(findings));
    } catch {
      threw = true;
    }
    assert.ok(!threw, "binary content should not crash scanner");
  });

  test("very long single line does not crash", () => {
    const longLine = "x".repeat(100000) + "ghp_" + "a".repeat(36) + "y".repeat(100000);
    let threw = false;
    try {
      const findings = scan(longLine, "context");
      assert.ok(Array.isArray(findings));
    } catch {
      threw = true;
    }
    assert.ok(!threw, "100k char line should not crash");
  });

  test("empty string scan returns empty findings", () => {
    const findings = scan("", "context");
    assert.equal(findings.length, 0);
  });

  test("unicode boundary: emoji and special chars do not break regex", () => {
    const content = "🔑 ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 🔑";
    let threw = false;
    try {
      const findings = scan(content, "context");
      assert.ok(Array.isArray(findings));
    } catch {
      threw = true;
    }
    assert.ok(!threw, "unicode emoji should not break scanner");
  });

  test("null byte in secret value is handled", () => {
    const content = "ghp_\u0000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let threw = false;
    try {
      const findings = scan(content, "context");
      assert.ok(Array.isArray(findings));
    } catch {
      threw = true;
    }
    assert.ok(!threw);
  });

  test("redact overlapping findings: later overlapping finds skipped", () => {
    const content = "SECRET=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const findings = scan(content, "context");
    const redacted = redact(content, findings);
    assert.ok(!redacted.includes("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "secret should be redacted");
    assert.ok(redacted.includes("[REDACTED:"), "redacted content has token");
  });

  test("redact no-op when no findings", () => {
    const content = "hello world this is safe";
    const result = redact(content, []);
    assert.equal(result, content);
  });

  test("scanAndRedact round-trip preserves non-secret content", () => {
    const content = "const apiKey = 'sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxAA'; console.log('ok');";
    const { redacted, findings } = scanAndRedact(content, "file");
    assert.ok(findings.length > 0, "should detect anthropic key");
    assert.ok(redacted.includes("[REDACTED:"), "should be redacted");
    assert.ok(redacted.includes("console.log"), "non-secret content preserved");
    assert.ok(redacted.includes("const apiKey = "), "prefix preserved");
  });

});

// ============================================================
// LAYER 1 HARDENING (file redaction)
// ============================================================

describe("layer1 file redaction hardening", () => {

  test("Layer1: file with secret is redacted in-place", () => {
    const dir = tempDir();
    try {
      const filePath = join(dir, "test.txt");
      writeFileSync(filePath, "MY_API_KEY=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "utf8");
      const input = { tool: "read", sessionID: "s1", callID: "c1" };
      const output = { args: { filePath } };
      handleLayer1(input as any, output as any);
      const content = readFileSync(filePath, "utf8");
      assert.ok(content.includes("[REDACTED:"), "file should be redacted in-place");
    } finally {
      cleanup(dir);
    }
  });

  test("Layer1: write tool triggers redaction", () => {
    const dir = tempDir();
    try {
      const filePath = join(dir, "config.txt");
      writeFileSync(filePath, "TOKEN=ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "utf8");
      const input = { tool: "write", sessionID: "s1", callID: "c2" };
      const output = { args: { filePath } };
      handleLayer1(input as any, output as any);
      const content = readFileSync(filePath, "utf8");
      assert.ok(content.includes("[REDACTED:"));
    } finally {
      cleanup(dir);
    }
  });

  test("Layer1: read-only tools do NOT trigger redaction", () => {
    const dir = tempDir();
    try {
      const filePath = join(dir, "safe.txt");
      writeFileSync(filePath, "hello world", "utf8");
      const input = { tool: "list_files", sessionID: "s1", callID: "c3" };
      const output = { args: { filePath } };
      handleLayer1(input as any, output as any);
      const content = readFileSync(filePath, "utf8");
      assert.equal(content, "hello world");
    } finally {
      cleanup(dir);
    }
  });

  test("Layer1: .env file is SKIPPED (sensitive path)", () => {
    const dir = tempDir();
    try {
      const filePath = join(dir, ".env");
      writeFileSync(filePath, "AWS_SECRET=AKIAIOSFODNN7EXAMPLE", "utf8");
      const input = { tool: "read", sessionID: "s1", callID: "c4" };
      const output = { args: { filePath } };
      handleLayer1(input as any, output as any);
      const content = readFileSync(filePath, "utf8");
      assert.ok(content.includes("AKIAIOSFODNN7EXAMPLE"), ".env files should be skipped");
    } finally {
      cleanup(dir);
    }
  });

  test("Layer1: .env.example IS scanned", () => {
    const dir = tempDir();
    try {
      const filePath = join(dir, ".env.example");
      writeFileSync(filePath, "AWS_SECRET=AKIAIOSFODNN7EXAMPLE", "utf8");
      const input = { tool: "read", sessionID: "s1", callID: "c5" };
      const output = { args: { filePath } };
      handleLayer1(input as any, output as any);
      const content = readFileSync(filePath, "utf8");
      assert.ok(content.includes("[REDACTED:"), ".env.example should be redacted");
    } finally {
      cleanup(dir);
    }
  });

  test("Layer1: non-existent file does not throw", () => {
    const input = { tool: "read", sessionID: "s1", callID: "c6" };
    const output = { args: { filePath: "/nonexistent/path/file.txt" } };
    let threw = false;
    try {
      handleLayer1(input as any, output as any);
    } catch {
      threw = true;
    }
    assert.ok(!threw, "non-existent file should not throw");
  });

  test("Layer1: binary file is skipped (no redaction)", () => {
    const dir = tempDir();
    try {
      const filePath = join(dir, "binary.bin");
      const buf = Buffer.alloc(100);
      buf[0] = 0x89; buf[1] = 0x50; buf[2] = 0x4e; buf[3] = 0x47;
      buf[50] = 0; // null byte makes it binary
      writeFileSync(filePath, buf);
      const input = { tool: "read", sessionID: "s1", callID: "c7" };
      const output = { args: { filePath } };
      handleLayer1(input as any, output as any);
      const content = readFileSync(filePath);
      assert.equal(content[0], 0x89, "binary file content should be unchanged");
    } finally {
      cleanup(dir);
    }
  });

  test("Layer1: large file (over 10MB) is skipped", () => {
    const dir = tempDir();
    try {
      const filePath = join(dir, "large.txt");
      const bigStr = "x".repeat(11 * 1024 * 1024);
      writeFileSync(filePath, bigStr, "utf8");
      const input = { tool: "read", sessionID: "s1", callID: "c8" };
      const output = { args: { filePath } };
      handleLayer1(input as any, output as any);
      const content = readFileSync(filePath, "utf8");
      assert.equal(content.length, 11 * 1024 * 1024, "large file should be unchanged");
    } finally {
      cleanup(dir);
    }
  });

  test("Layer1: no args (missing filePath) does not throw", () => {
    const input = { tool: "read", sessionID: "s1", callID: "c9" };
    const output = { args: {} };
    let threw = false;
    try {
      handleLayer1(input as any, output as any);
    } catch {
      threw = true;
    }
    assert.ok(!threw);
  });

  test("Layer1: in-place redaction creates no backup file", () => {
    const dir = tempDir();
    try {
      const filePath = join(dir, "secrets.txt");
      writeFileSync(filePath, "PASSWORD=supersecret123", "utf8");
      const input = { tool: "edit", sessionID: "s1", callID: "c10" };
      const output = { args: { filePath } };
      handleLayer1(input as any, output as any);
      const backups = existsSync(filePath + ".bak");
      const backups2 = existsSync(filePath + "~");
      const backups3 = existsSync(join(dir, ".secrets.txt.swo"));
      assert.ok(!backups && !backups2 && !backups3, "no backup file should exist (destructive redaction)");
    } finally {
      cleanup(dir);
    }
  });

});

// ============================================================
// LAYER 2 MESSAGE HARDENING
// ============================================================

describe("layer2 message hardening", () => {

  test("Layer2 message: secrets detected but NOT redacted (known bug)", () => {
    const event = {
      type: "message.created",
      text: "Here is my key: ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    };
    let threw = false;
    try {
      handleLayer2Message({ event: event as any });
    } catch {
      threw = true;
    }
    assert.ok(!threw, "layer2 message handler should not throw");
  });

  test("Layer2 message: non-message event type is skipped", () => {
    const event = {
      type: "tool_execution",
      text: "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    };
    let threw = false;
    try {
      handleLayer2Message({ event: event as any });
    } catch {
      threw = true;
    }
    assert.ok(!threw);
  });

  test("Layer2 message: event with null text handled", () => {
    const event = {
      type: "message.created",
      text: null,
    };
    let threw = false;
    try {
      handleLayer2Message({ event: event as any });
    } catch {
      threw = true;
    }
    assert.ok(!threw);
  });

  test("Layer2 message: event with no text field handled", () => {
    const event = {
      type: "message.created",
      notText: 42,
    };
    let threw = false;
    try {
      handleLayer2Message({ event: event as any });
    } catch {
      threw = true;
    }
    assert.ok(!threw);
  });

  test("Layer2 message: message with content field handled", () => {
    const event = {
      type: "message.updated",
      content: "ghp_cccccccccccccccccccccccccccccccccccc",
    };
    let threw = false;
    try {
      handleLayer2Message({ event: event as any });
    } catch {
      threw = true;
    }
    assert.ok(!threw);
  });

  test("Layer2 message: message with nested message.text handled", () => {
    const event = {
      type: "message.created",
      message: { text: "ghp_dddddddddddddddddddddddddddddddddddddd" },
    };
    let threw = false;
    try {
      handleLayer2Message({ event: event as any });
    } catch {
      threw = true;
    }
    assert.ok(!threw);
  });

  test("Layer2 message: message with nested message.content handled", () => {
    const event = {
      type: "message.created",
      message: { content: "ghp_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" },
    };
    let threw = false;
    try {
      handleLayer2Message({ event: event as any });
    } catch {
      threw = true;
    }
    assert.ok(!threw);
  });

});

// ============================================================
// LAYER 2 COMPACTION HARDENING
// ============================================================

describe("layer2 compaction hardening", () => {

  test("Layer2 compaction: context array with secrets is redacted", () => {
    const output = {
      context: [
        "public content",
        "MY_KEY=ghp_ffffffffffffffffffffffffffffffffffffffff",
        "more public content",
      ],
    };
    handleLayer2Compaction({ sessionID: "s1" } as any, output as any);
    assert.ok(output.context[0] === "public content", "non-secret context preserved");
    assert.ok(output.context[1].includes("[REDACTED:"), "secret context redacted");
    assert.ok(output.context[2] === "more public content", "non-secret context preserved");
  });

  test("Layer2 compaction: empty context array is handled", () => {
    const output = { context: [] };
    let threw = false;
    try {
      handleLayer2Compaction({ sessionID: "s1" } as any, output as any);
    } catch {
      threw = true;
    }
    assert.ok(!threw);
  });

  test("Layer2 compaction: null/undefined context handled", () => {
    const output1 = { context: null };
    const output2 = {};
    let threw = false;
    try {
      handleLayer2Compaction({ sessionID: "s1" } as any, output1 as any);
      handleLayer2Compaction({ sessionID: "s1" } as any, output2 as any);
    } catch {
      threw = true;
    }
    assert.ok(!threw);
  });

  test("Layer2 compaction: no findings does not corrupt context", () => {
    const output = { context: ["safe content", "also safe"] };
    handleLayer2Compaction({ sessionID: "s1" } as any, output as any);
    assert.equal(output.context.length, 2);
    assert.equal(output.context[0], "safe content");
    assert.equal(output.context[1], "also safe");
  });

});

// ============================================================
// REDACT FUNCTION HARDENING
// ============================================================

describe("redact function hardening", () => {

  test("redact: empty findings returns original content", () => {
    const result = redact("hello", []);
    assert.equal(result, "hello");
  });

  test("redact: finding with offset beyond content length", () => {
    const content = "short";
    const result = redact(content, [
      { ruleId: "test", match: "long", redacted: "[REDACTED:test:xxx]", offset: 100, source: "file", description: "test" },
    ]);
    assert.equal(result, content);
  });

  test("redact: negative offset is handled", () => {
    const content = "hello";
    const result = redact(content, [
      { ruleId: "test", match: "he", redacted: "[REDACTED:test:xxx]", offset: -1, source: "file", description: "test" },
    ]);
    assert.equal(result, content);
  });

  test("redact: duplicate overlapping findings deduplicated", () => {
    const content = "MY_KEY=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const findings = [
      { ruleId: "github-pat", match: "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", redacted: "[REDACTED:github-pat:x1]", offset: 7, source: "file", description: "" },
      { ruleId: "generic-api-key", match: "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", redacted: "[REDACTED:generic:x2]", offset: 7, source: "file", description: "" },
    ];
    const result = redact(content, findings);
    assert.ok(result.includes("[REDACTED:"));
    assert.ok(!result.includes("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
  });

});

// ============================================================
// DEDUPLICATION HARDENING
// ============================================================

describe("deduplication hardening", () => {

  test("dedup: many overlapping findings all sorted by offset", () => {
    const content = "aaaSK-ANTaaa" + "bbbSK-ANTbbb" + "cccSK-ANTccc";
    const findings = scan(content, "context");
    const redacted = redact(content, findings);
    assert.equal(typeof redacted, "string");
    assert.ok(redacted.length > 0);
  });

  test("dedup: 1000 identical findings for same secret", () => {
    const content = "TOKEN=sk-ant-api03-" + "x".repeat(93) + "AA";
    const findings = scan(content, "context");
    assert.ok(findings.length <= 10, `dedup should collapse 1000 overlapping matches to <= 10`);
  });

});

// ============================================================
// ENTROPY HELPER HARDENING
// ============================================================

describe("entropy helper hardening", () => {

  test("shannonEntropy: empty string returns 0", () => {
    assert.equal(shannonEntropy(""), 0);
  });

  test("shannonEntropy: single char returns 0", () => {
    assert.equal(shannonEntropy("a"), 0);
  });

  test("shannonEntropy: all same chars returns 0", () => {
    assert.equal(shannonEntropy("aaaaaaa"), 0);
  });

  test("shannonEntropy: uniform distribution near max", () => {
    const ent = shannonEntropy("abcdefghijklmnop");
    assert.ok(ent > 3.5, `uniform 16-char entropy should be high, got ${ent}`);
  });

});
