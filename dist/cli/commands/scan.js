import { readFileSync, statSync, readdirSync } from "node:fs";
import { join, extname } from "node:path";
import { scanAndRedact } from "../../engine/scanner.js";
const SKIP_EXTENSIONS = new Set([
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".tiff", ".webp",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".o", ".obj",
    ".lock", ".lockb",
]);
function isBinary(content) {
    for (let i = 0; i < Math.min(content.length, 8192); i++) {
        if (content[i] === 0)
            return true;
    }
    return false;
}
function scanFile(filePath, source) {
    const raw = readFileSync(filePath);
    if (isBinary(raw))
        return { findings: [], redacted: "" };
    const content = raw.toString("utf8");
    return scanAndRedact(content, source, filePath);
}
function scanDirectory(dirPath, source) {
    const allFindings = [];
    function walk(dir) {
        const entries = readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
            const fullPath = join(dir, entry.name);
            if (entry.name === "node_modules" || entry.name === ".git")
                continue;
            if (entry.isDirectory()) {
                walk(fullPath);
            }
            else if (entry.isFile()) {
                const ext = extname(entry.name).toLowerCase();
                if (SKIP_EXTENSIONS.has(ext))
                    continue;
                try {
                    const { findings } = scanFile(fullPath, source);
                    for (const f of findings) {
                        allFindings.push({ ...f, match: `${fullPath}: ${f.match}` });
                    }
                }
                catch {
                    // Skip files we can't read
                }
            }
        }
    }
    walk(dirPath);
    return allFindings;
}
export async function cmdScan(positional, flags) {
    const source = flags.source || "file";
    const asJson = !!flags.json;
    if (positional.length === 0) {
        console.error("Usage: sd scan <file|directory|->");
        process.exit(1);
    }
    const target = positional[0];
    if (target === "-") {
        let input = "";
        for await (const chunk of process.stdin) {
            input += chunk.toString();
        }
        const { findings } = scanAndRedact(input, source);
        if (asJson) {
            console.log(JSON.stringify(findings, null, 2));
        }
        else if (findings.length === 0) {
            console.log("No secrets detected.");
        }
        else {
            for (const f of findings) {
                console.log(`${f.ruleId}: ${f.description}`);
                console.log(`  Redacted: ${f.redacted}`);
            }
        }
        return;
    }
    try {
        const stats = statSync(target);
        let findings;
        if (stats.isDirectory()) {
            findings = scanDirectory(target, source);
        }
        else {
            const result = scanFile(target, source);
            findings = result.findings;
        }
        if (asJson) {
            console.log(JSON.stringify(findings, null, 2));
        }
        else if (findings.length === 0) {
            console.log(`No secrets detected in ${target}.`);
        }
        else {
            console.log(`Found ${findings.length} secret(s) in ${target}:`);
            for (const f of findings) {
                console.log(`  ${f.ruleId}: ${f.description}`);
                console.log(`    Redacted: ${f.redacted}`);
            }
        }
    }
    catch (err) {
        console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
    }
}
//# sourceMappingURL=scan.js.map