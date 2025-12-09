# PNPM Security Scanner

Detect compromised npm packages in your Node.js projects.

A fast, zero-dependency CLI tool that scans your dependencies against a database of known malicious packages. Works with **npm**, **pnpm**, and **yarn** — any project with a `package.json`.

> **Inspired by the [Shai-Hulud npm worm](https://socket.dev/blog/shai-hulud-npm-worm)** — a self-replicating malware that infected 187+ packages with 2M+ weekly downloads in September 2025.

---

## 🌐 Web UI

Try the scanner without installing anything: **[security-scanner.araptus.com](https://security-scanner.araptus.com)**

Just drag & drop your `package.json` or lock file and get instant results.

---

## Quick Start

```bash
# Copy to your project
cp scripts/security-scan.js your-project/scripts/
cp -r security/ your-project/security/

# Make executable
chmod +x scripts/security-scan.js

# Run
node scripts/security-scan.js
```

Add to `package.json`:

```json
{
  "scripts": {
    "security:scan": "node scripts/security-scan.js"
  }
}
```

---

## Usage

```bash
# Quick scan (direct dependencies only)
pnpm run security:scan

# Deep scan (all transitive dependencies via lock file)
pnpm run security:scan --deep

# Detailed output
pnpm run security:scan --verbose

# JSON output (CI/CD)
pnpm run security:scan --json

# Strict mode (fail on any risk)
pnpm run security:scan --strict

# Combine flags
pnpm run security:scan --deep --strict --json
```

---

## What It Detects

- **137+ known malicious packages**
- **Shai-Hulud malware** (187+ packages)
- **PhantomRaven campaign** (126 packages)
- **Typosquatting variants** (66 packages)
- **Credential theft packages** (25 packages)
- **Crypto mining malware** (13 packages)

---

## Deep Scanning

Use `--deep` to scan **transitive dependencies** from your lock file. This is where most supply chain attacks hide.

```bash
pnpm run security:scan --deep
```

Supported lock files:
- `pnpm-lock.yaml` (pnpm)
- `package-lock.json` (npm)
- `yarn.lock` (yarn)

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npx @kris-araptus/npm-security-scanner --deep --strict
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Clean |
| `1` | Issues found |
| `2` | Error |

---

## CLI Options

| Option | Short | Description |
|--------|-------|-------------|
| `--verbose` | `-v` | Show detailed output for each package |
| `--json` | | Output results in JSON format |
| `--strict` | | Fail on any risk level (not just critical/high) |
| `--deep` | `-d` | Scan transitive dependencies from lock file |
| `--help` | `-h` | Show help message |

---

## Update Threat Database

Edit `security/compromised-packages.json`:

```json
{
  "knownMalicious": {
    "confirmed": ["new-bad-package"]
  },
  "lastUpdated": "2025-12-09"
}
```

---

## Project Structure

```
├── scripts/
│   └── security-scan.js      # CLI scanner (zero dependencies)
├── security/
│   ├── compromised-packages.json  # Threat database
│   └── README.md             # Quick start guide
├── tests/
│   └── security-scan.test.js # Test suite
├── web/                      # Web UI (Astro + React + Tailwind)
│   ├── src/
│   │   ├── components/       # React components
│   │   ├── lib/              # Scanner logic + threat DB
│   │   └── pages/            # Astro pages + API
│   └── package.json
└── package.json
```

---

## Credits

- **Kris Araptus** — Original scanner and threat database
- **Jeremiah Coakley / FEDLIN** — Deep scanning and web UI

---

## License

MIT
