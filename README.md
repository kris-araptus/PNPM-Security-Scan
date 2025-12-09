# npm Security Scanner

Detect compromised npm packages in your Node.js projects.

A fast, zero-dependency CLI tool that scans your dependencies against a database of known malicious packages.

> **Inspired by the [Shai-Hulud npm worm](https://socket.dev/blog/shai-hulud-npm-worm)** — a self-replicating malware that infected 187+ packages with 2M+ weekly downloads in September 2025.

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
# Quick scan
pnpm run security:scan

# Detailed output
pnpm run security:scan --verbose

# JSON output (CI/CD)
pnpm run security:scan --json

# Strict mode (fail on any risk)
pnpm run security:scan --strict
```

---

## What It Detects

- **42+ confirmed malicious packages**
- **Shai-Hulud malware** (187+ packages)
- **Crypto hijacking** (18 packages)
- **Typosquatting variants**
- **Credential theft packages**

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Clean |
| `1` | Issues found |
| `2` | Error |

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

## License

MIT
