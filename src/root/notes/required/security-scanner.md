# Security Scanner - Quick Reference

> Cheat sheet for daily use

---

## 🚀 Essential Commands

```bash
# Quick scan
pnpm run security:scan

# Detailed scan
pnpm run security:scan:verbose

# CI/CD mode
pnpm run security:scan --strict --json

# Full audit
pnpm run security:full
```

---

## ⚡ CLI Options

| Option | What it does |
|--------|--------------|
| `--verbose` / `-v` | Show each package |
| `--json` | JSON output |
| `--strict` | Fail on any risk |
| `--help` / `-h` | Show help |

---

## 📊 Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Clean ✅ |
| `1` | Issues found ❌ |
| `2` | Error ⚠️ |

---

## 🎯 Daily Workflow

```bash
# Before commit
pnpm run security:scan

# Before deploy
pnpm run security:audit

# Weekly check
pnpm run security:full
```

---

## 🔧 Add a Threat

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

## ✅ Whitelist Package

```json
{
  "trustedPackages": {
    "packages": ["safe-package"]
  }
}
```

---

## 🐛 Quick Fixes

**Scanner won't run:**
```bash
chmod +x scripts/security-scan.js
```

**Database error:**
```bash
cat security/compromised-packages.json | jq .
```

---

## 📚 More Info

- Full docs: `docs/SECURITY-SCANNER.md`
- Threat DB: `security/compromised-packages.json`
- AI prompt: `README-SECURITY-SCANNER.md`

---

**v1.0.0** | Dec 2025




