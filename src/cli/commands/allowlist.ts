import { loadAllowlist } from "../../engine/allowlist.js";

export async function cmdAllowlist(subcommand: string, _positional: string[]): Promise<void> {
    if (subcommand === "show") {
        const allowlist = loadAllowlist();
        if (allowlist.entries.length === 0) {
            console.log("No allowlist entries.");
            return;
        }
        for (let i = 0; i < allowlist.entries.length; i++) {
            const e = allowlist.entries[i];
            console.log(`${i + 1}. ${e.description || "(no description)"}`);
            console.log(`   fingerprint: ${e.fingerprint || "—"}`);
            console.log(`   ruleId: ${e.ruleId || "—"}`);
            console.log(`   path: ${e.path || "—"}`);
            console.log(`   regex: ${e.regex || "—"}`);
        }
        return;
    }

    if (subcommand === "add") {
        console.log("Add allowlist entry. Choose a type:");
        console.log("  1. By fingerprint");
        console.log("  2. By rule ID");
        console.log("  3. By file path");
        console.log("  4. By regex pattern");
        console.log("");
        console.log("Usage examples:");
        console.log("  sd allowlist add --fingerprint a3f7b2c1 --description \"Known test key\"");
        console.log("  sd allowlist add --ruleId aws-access-token --description \"Internal AWS account\"");
        console.log("  sd allowlist add --path \"test/fixtures/*.ts\" --description \"Test fixtures\"");
        console.log("  sd allowlist add --regex \"EXAMPLE\" --description \"Example values\"");
        return;
    }

    console.log("Usage: sd allowlist <show|add> [options]");
}
