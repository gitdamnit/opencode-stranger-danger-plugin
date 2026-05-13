import type { Allowlist, AllowlistEntry } from "./types.js";
import type { Finding } from "./types.js";
export declare function loadAllowlist(path?: string): Allowlist;
export declare function saveAllowlistEntry(entry: AllowlistEntry, path?: string): void;
export declare function filterByAllowlist(findings: Finding[], allowlist: Allowlist): Finding[];
//# sourceMappingURL=allowlist.d.ts.map