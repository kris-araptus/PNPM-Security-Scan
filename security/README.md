# Security Scanner - Quick Start Guide

> Detect compromised npm packages in your Node.js projects

---

## 🚀 Quick Start

### Run a Scan

```bash
# Quick scan
pnpm run security:scan

# Detailed scan (shows each package)
pnpm run security:scan:verbose

# JSON output (for CI/CD)
pnpm run security:scan:json

# Strict mode (fails on any risk level)
pnpm run security:scan:strict
```

---

## 📊 Understanding Results

### Clean Scan (Exit Code 0)

```
✅ No security issues detected!
   All dependencies appear to be clean.

✅ Security scan PASSED
```

### Issues Found (Exit Code 1)

```
🚨 CRITICAL ISSUES (1)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ❌ malicious-package@1.0.0
     Type: Confirmed Malicious
     Reason: This package has been confirmed as malicious
     Action: REMOVE IMMEDIATELY

📋 RECOMMENDED ACTIONS:
  1. IMMEDIATELY remove critical packages
  2. Check for data exfiltration in logs
  3. Rotate all credentials and tokens
```

---

## ⚡ Severity Levels

| Level | Icon | Meaning | Action |
|-------|------|---------|--------|
| **Critical** | ❌ | Confirmed malicious | Remove immediately |
| **High** | ⚠ | Part of attack campaign | Check version, update |
| **Medium** | ⚡ | Potentially affected | Verify and monitor |
| **Low** | ℹ | Minor risk | Review when possible |

---

## 🔧 CLI Options

| Option | Short | Description |
|--------|-------|-------------|
| `--verbose` | `-v` | Show detailed output |
| `--json` | | JSON output for parsing |
| `--strict` | | Fail on any risk level |
| `--help` | `-h` | Show help message |

---

## 📁 Threat Database

**Location:** `security/compromised-packages.json`

**Current Coverage:**
- 42+ known malicious packages
- 3 major 2025 attack campaigns
- Typosquatting protection
- Version-specific threats

### Adding a Threat

Edit `security/compromised-packages.json`:

```json
{
  "knownMalicious": {
    "confirmed": [
      "existing-package",
      "new-malicious-package"  // Add here
    ]
  },
  "lastUpdated": "2025-12-09"  // Update this
}
```

### Whitelisting a Package

```json
{
  "trustedPackages": {
    "packages": [
      "@your-org/*",
      "safe-package"
    ]
  }
}
```

---

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
- name: Security scan
  run: pnpm run security:scan --strict
```

### Exit Codes

- `0` = Clean ✅
- `1` = Issues found ❌
- `2` = Configuration error ⚠️

---

## 📚 More Documentation

- **Complete Guide:** `docs/SECURITY-SCANNER.md`
- **AI Prompt:** `README-SECURITY-SCANNER.md`
- **Quick Reference:** `PROMPT-SECURITY-SCANNER.md`

---

## 🆘 Troubleshooting

**Scanner won't run:**
```bash
chmod +x scripts/security-scan.js
node scripts/security-scan.js
```

**Database error:**
```bash
cat security/compromised-packages.json | jq .
```

**False positive:**
Add to `trustedPackages.packages` in the database.

---

**Version:** 1.0.0 | **Updated:** December 9, 2025

