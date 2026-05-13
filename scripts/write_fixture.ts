import fs from "node:fs";

const pem = `-----BEGIN PRIVATE KEY-----
FAKE_PRIVATE_KEY_FOR_TESTS_ONLY_DO_NOT_USE
-----END PRIVATE KEY-----`;

const openai = "OPENAI_FAKE_KEY_FOR_TESTS_NOT_REAL";
const anthropic = "ANTHROPIC_FAKE_KEY_FOR_TESTS_NOT_REAL";

const fixture = `
// AWS Access Key - defanged test fixture
const AWS_KEY = "AWS_FAKE_ACCESS_KEY_FOR_TESTS_NOT_REAL";

// GitHub token - defanged test fixture
const GH_TOKEN = "GITHUB_FAKE_TOKEN_FOR_TESTS_NOT_REAL";

// OpenAI API Key - defanged test fixture
const OPENAI_KEY = "${openai}";

// Anthropic API Key - defanged test fixture
const ANTHROPIC_KEY = "${anthropic}";

// Stripe Secret Key - defanged test fixture
const STRIPE_KEY = "STRIPE_FAKE_SECRET_KEY_FOR_TESTS_NOT_REAL";

// Groq API Key - defanged test fixture
const GROQ_KEY = "GROQ_FAKE_KEY_FOR_TESTS_NOT_REAL";

// MongoDB connection string with fake credentials
const MONGO_URI = "mongodb+srv://fake_user:fake_password@cluster0.example.invalid/mydb";

// Supabase token - defanged test fixture
const SUPABASE_TOKEN = "SUPABASE_FAKE_TOKEN_FOR_TESTS_NOT_REAL";

// Private Key - defanged test fixture
const PRIVATE_KEY = \`${pem}\`;

// JWT token - defanged test fixture
const JWT_TOKEN = "JWT_FAKE_TOKEN_FOR_TESTS_NOT_REAL";
`;

fs.writeFileSync(
  "/home/evan/Desktop/Projects/cheapcode/module7-stranger-danger-plugin/tests/fixtures/dirty.ts",
  fixture
);

console.log("Fixture written");
