// Entropy edge cases — high-entropy non-secrets that must NOT false-positive

export const entropyEdgeContent = `
// UUIDs — structured, low entropy per charset
const UUID1 = "550e8400-e29b-41d4-a716-446655440000";
const UUID2 = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";

// SHA256 hashes — high entropy but well-known format
const HASH1 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// English sentences — low entropy
const SENTENCE = "The quick brown fox jumps over the lazy dog";
const CODE_COMMENT = "This function handles the main application logic";

// Short strings — below minimum length
const SHORT1 = "abc123";
const SHORT2 = "test";

// All same character — zero entropy
const REPEATED = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const REPEATED2 = "1111111111111111111111111111111111111111";

// Version strings
const VERSION = "1.2.3-alpha.4+build.5678";

// CSS color codes
const COLOR = "#abcdef";
`;
