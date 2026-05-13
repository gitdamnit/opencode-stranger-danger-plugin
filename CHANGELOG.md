# Changelog

## 0.1.0 (2026-05-08)

Initial release.

### Features

- Three-layer secret scanning: file-level, context-level, output-level
- ~160 rules vendored from gitleaks (MIT)
- ~12 clean-room additions for AI/ML providers (Groq, DeepSeek, Replicate, ElevenLabs, W&B, LangSmith, LangFuse, Supabase, Vercel, MongoDB, PostgreSQL, Redis)
- 3 entropy-based detectors (Base64, Hex, Alphanumeric)
- OpenCode plugin with hooks: `tool.execute.before`, `experimental.session.compacting`, `tool.execute.after`, `event`
- OpenCode tools: `sd_status`, `sd_audit`, `sd_allowlist_add`, `sd_allowlist_show`, `sd_scan`
- Standalone CLI: `sd scan`, `sd redact`, `sd audit`, `sd rules`, `sd allowlist`
- Deterministic SHA-256 fingerprinting for redaction tokens
- JSONL audit log (never stores secret values)
- TOML allowlist support (by fingerprint, ruleId, path, regex)
- Zero runtime dependencies
