import { NAMED_RULES, ENTROPY_RULES, CLEAN_ROOM_RULES } from "../../engine/rules.js";
export async function cmdRules() {
    const allRules = [...NAMED_RULES, ...CLEAN_ROOM_RULES, ...ENTROPY_RULES];
    console.log(`Total rules: ${allRules.length}`);
    console.log(`  Named rules (gitleaks): ${NAMED_RULES.length}`);
    console.log(`  Clean-room additions: ${CLEAN_ROOM_RULES.length}`);
    console.log(`  Entropy detectors: ${ENTROPY_RULES.length}`);
    console.log("");
    for (const rule of allRules) {
        console.log(`${rule.id}: ${rule.description}`);
        if (rule.keywords.length > 0) {
            console.log(`  Keywords: ${rule.keywords.join(", ")}`);
        }
        if (rule.entropy !== undefined) {
            console.log(`  Entropy threshold: ${rule.entropy}`);
        }
    }
}
//# sourceMappingURL=rules.js.map