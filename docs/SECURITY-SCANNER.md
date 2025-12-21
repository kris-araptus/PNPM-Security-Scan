# npm Security Scanner - Complete Guide

A comprehensive CLI tool for detecting compromised npm packages in Node.js projects.

---

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Usage](#usage)
4. [Configuration](#configuration)
5. [Threat Database](#threat-database)
6. [CI/CD Integration](#cicd-integration)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)
9. [Contributing](#contributing)

---

## Overview

### What It Does

The npm Security Scanner checks your project's dependencies against a local database of known compromised packages. It detects:

- **Confirmed malicious packages** - Packages known to contain malware
- **Campaign-specific threats** - Packages compromised in coordinated attacks
- **Typosquatting variants** - Fake packages with similar names to popular ones
- **Credential theft packages** - Packages that steal tokens and credentials

### Why It Exists

Built in response to major 2025 supply chain attacks:

| Campaign | Affected | Impact |
|----------|----------|--------|
| Shai-Hulud Malware | 187+ packages | 2M+ weekly downloads |
| Crypto Hijacking | 18 packages | 2.6B+ weekly downloads |
| Token Farming | 150,000+ packages | Metric manipulation |

---

## Installation

### Option 1: Use in Existing Project

```bash
# Copy files to your project
cp -r scripts/ your-project/scripts/
cp -r security/ your-project/security/

# Make executable
chmod +x scripts/security-scan.js

# Add scripts to package.json
```

### Option 2: Clone Repository

```bash
git clone https://github.com/kris-araptus/npm-security-scanner
cd npm-security-scanner
pnpm install
```

### Package.json Scripts

Add these to your `package.json`:

```json
{
  "scripts": {
    "security:scan": "node scripts/security-scan.js",
    "security:scan:verbose": "node scripts/security-scan.js --verbose",
    "security:scan:json": "node scripts/security-scan.js --json",
    "security:scan:strict": "node scripts/security-scan.js --strict",
    "security:audit": "pnpm audit --prod && node scripts/security-scan.js",
    "security:full": "pnpm audit; pnpm outdated || true; node scripts/security-scan.js --verbose"
  }
}
```

---

## Usage

### Basic Commands

```bash
# Quick scan (recommended for daily use)
pnpm run security:scan

# Verbose scan (shows each package checked)
pnpm run security:scan:verbose

# JSON output (for CI/CD parsing)
pnpm run security:scan:json

# Strict mode (fails on any risk)
pnpm run security:scan:strict

# Combined with npm audit
pnpm run security:audit

# Full security check
pnpm run security:full
```

### CLI Options

| Option | Alias | Description |
|--------|-------|-------------|
| `--verbose` | `-v` | Show detailed output for each package |
| `--json` | | Output results as JSON |
| `--strict` | | Fail on any risk level (not just critical/high) |
| `--help` | `-h` | Display help message |

### Exit Codes

| Code | Meaning | When |
|------|---------|------|
| `0` | Success | No issues found |
| `1` | Failed | Critical or high severity issues |
| `2` | Error | Configuration or runtime error |

---

## Configuration

### Threat Database Location

The scanner looks for `compromised-packages.json` in these locations (in order):

1. `./security/compromised-packages.json`
2. `./compromised-packages.json`
3. `../security/compromised-packages.json` (relative to script)

### Database Schema

```json
{
  "version": "1.0.0",
  "lastUpdated": "YYYY-MM-DD",
  "sources": ["url1", "url2"],
  
  "campaigns": {
    "campaign-id": {
      "name": "Campaign Name",
      "date": "YYYY-MM",
      "severity": "critical|high|medium|low",
      "description": "What it does",
      "packages": ["pkg1", "pkg2"],
      "affectedVersions": {
        "pkg1": ["1.0.0", "1.0.1"]
      }
    }
  },
  
  "knownMalicious": {
    "confirmed": ["package1"],
    "typosquatting": ["fake-pkg"],
    "credentialTheft": ["stealer"]
  },
  
  "trustedPackages": {
    "packages": ["@scope/*", "safe-pkg"]
  }
}
```

### Customizing the Database

#### Add a Malicious Package

```json
{
  "knownMalicious": {
    "confirmed": [
      "existing-malicious-pkg",
      "new-malicious-pkg"
    ]
  }
}
```

#### Add a Campaign

```json
{
  "campaigns": {
    "new-attack-2025": {
      "name": "New Attack Campaign",
      "date": "2025-12",
      "severity": "critical",
      "description": "Description of the attack",
      "packages": ["affected-pkg"],
      "affectedVersions": {
        "affected-pkg": ["1.0.0"]
      }
    }
  }
}
```

#### Whitelist a Package

```json
{
  "trustedPackages": {
    "packages": [
      "@your-org/*",
      "trusted-package"
    ]
  }
}
```

---

## Threat Database

### Current Coverage (Dec 2025)

| Category | Count |
|----------|-------|
| Confirmed Malicious | 42+ |
| Attack Campaigns | 3 |
| Typosquatting Variants | 30+ |
| Credential Theft | 15+ |
| Trusted Patterns | 30+ |

### Updating the Database

**Check these sources weekly:**

1. **GitHub Advisories**
   - https://github.com/advisories?query=ecosystem%3Anpm

2. **Socket.dev Blog**
   - https://socket.dev/blog

3. **Snyk Vulnerability Database**
   - https://snyk.io/vuln

4. **npm Security Advisories**
   - https://www.npmjs.com/advisories

### Update Workflow

1. Check security sources for new threats
2. Add to appropriate section in `compromised-packages.json`
3. Update `lastUpdated` field
4. Test: `pnpm run security:scan:verbose`
5. Commit and push changes

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup pnpm
        uses: pnpm/action-setup@v2
        with:
          version: 8
          
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'pnpm'
          
      - name: Install dependencies
        run: pnpm install
        
      - name: Run security scan
        run: pnpm run security:scan --strict
```

### GitLab CI

```yaml
security_scan:
  stage: test
  script:
    - pnpm install
    - pnpm run security:scan --strict
  allow_failure: false
```

### Pre-commit Hook

Using Husky:

```json
{
  "husky": {
    "hooks": {
      "pre-commit": "pnpm run security:scan"
    }
  }
}
```

### JSON Output for Parsing

```bash
pnpm run security:scan --json > security-report.json
```

Output structure:

```json
{
  "timestamp": "2025-12-09T10:30:00.000Z",
  "packagesScanned": 28,
  "totalIssues": 0,
  "results": {
    "critical": [],
    "high": [],
    "medium": [],
    "low": []
  }
}
```

---

## Best Practices

### Daily Workflow

```bash
# Before committing
git add .
pnpm run security:scan
git commit -m "message"
```

### Before Deploying

```bash
pnpm run security:audit
pnpm run build
pnpm run deploy
```

### Weekly Maintenance

```bash
pnpm run security:full
pnpm outdated
```

### Security Hygiene

1. **Run scans before every commit**
2. **Integrate into CI/CD pipeline**
3. **Update threat database weekly**
4. **Monitor security advisory sources**
5. **Review lock files for unexpected changes**
6. **Use strict mode in production pipelines**

---

## Troubleshooting

### Scanner Won't Run

```bash
# Make executable
chmod +x scripts/security-scan.js

# Run directly
node scripts/security-scan.js

# Check Node version (requires 18+)
node --version
```

### Database Not Found

```bash
# Check file exists
ls security/compromised-packages.json

# Check from script directory
ls scripts/../security/compromised-packages.json
```

### Invalid JSON Error

```bash
# Validate JSON
cat security/compromised-packages.json | jq .

# Or use Node
node -e "JSON.parse(require('fs').readFileSync('security/compromised-packages.json', 'utf8'))"
```

### False Positives

If a safe package is flagged:

1. Verify it's actually safe (check multiple sources)
2. Add to `trustedPackages.packages` in the database
3. Test the scanner again

```json
{
  "trustedPackages": {
    "packages": [
      "falsely-flagged-package"
    ]
  }
}
```

### Package Not Being Detected

1. Check package name matches exactly (case-sensitive)
2. Verify it's not in `trustedPackages`
3. Add to appropriate malicious category
4. Update `lastUpdated` field
5. Test with verbose mode

---

## Contributing

### Adding New Threats

1. **Verify the threat** - Confirm from multiple sources (GitHub, Socket.dev, Snyk)
2. **Document the threat** - Include severity, description, affected versions
3. **Add to database** - Edit `security/compromised-packages.json`
4. **Update metadata** - Change `lastUpdated` field
5. **Test** - Run `pnpm run security:scan:verbose`
6. **Submit PR** - Include sources and verification

### Reporting False Positives

1. Open an issue with package name
2. Provide evidence it's safe
3. Include npm page, GitHub repo links
4. We'll review and update the whitelist

### Improving the Scanner

1. Read the implementation: `scripts/security-scan.js`
2. Test changes with all output modes
3. Maintain backward compatibility
4. Preserve exit codes (0, 1, 2)
5. Update documentation

---

## Version History

### v1.0.0 (December 2025)

- Initial release
- CLI scanner with colored output
- JSON threat database
- 42+ known malicious packages
- 3 major attack campaigns
- Multiple output modes
- CI/CD integration support
- Complete documentation

---

## Resources

### Security Sources

- GitHub Advisories: https://github.com/advisories
- Socket.dev: https://socket.dev
- Snyk: https://snyk.io/vuln
- npm Security: https://www.npmjs.com/advisories

### Attack Research

- Shai-Hulud: https://www.techradar.com/pro/security/self-replicating-shai-hulud
- Crypto Hijacking: https://jfrog.com/blog
- Token Farming: https://www.endorlabs.com/learn

### Tools & Standards

- OWASP Dependency Check: https://owasp.org
- SLSA Framework: https://slsa.dev

---

**Version:** 1.0.0  
**Last Updated:** December 9, 2025  
**Status:** ✅ Production Ready









