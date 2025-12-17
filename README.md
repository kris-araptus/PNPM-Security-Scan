# PNPM Security Scanner

Detect compromised npm packages in your Node.js projects.

A fast, zero-dependency CLI tool that scans your dependencies against a database of known malicious packages. Works with **npm**, **pnpm**, and **yarn** — any project with a `package.json`.

> **Inspired by the [Shai-Hulud npm worm](https://socket.dev/blog/shai-hulud-npm-worm)** — a self-replicating malware that infected 187+ packages with 2M+ weekly downloads in September 2025.


## Quick Start

```bash
# Clone or copy to your project
git clone https://github.com/your-repo/pnpm-security-scan.git
cd pnpm-security-scan

# Install (optional - zero dependencies for core scanner)
pnpm install

# Run
node scripts/security-scan.js
```

Or copy the scanner into an existing project:

```bash
cp scripts/security-scan.js your-project/scripts/
cp -r security/ your-project/security/
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

# Check postinstall scripts for suspicious patterns
pnpm run security:scan -- --analyze-scripts

# Generate HTML report
pnpm run security:scan -- --report

# JSON output (for CI/CD pipelines)
pnpm run security:scan -- --json

# Ignore specific packages
pnpm run security:scan -- --ignore pkg1,pkg2

# Strict mode (fail on any risk)
pnpm run security:scan --strict

# Combine flags
pnpm run security:scan --deep --strict --json

# Auto-fix (remove malicious packages)
pnpm run security:scan -- --fix --yes
```

---

## CLI Options

| Option | Description |
|--------|-------------|
| `--verbose, -v` | Show detailed output |
| `--deep` | Scan transitive dependencies (node_modules) |
| `--analyze-scripts` | Check postinstall scripts for suspicious patterns |
| `--strict` | Fail on any risk level |
| `--json` | JSON output for parsing |
| `--silent, -s` | Suppress output (exit code only) |
| `--report` | Generate `security-report.html` |
| `--ignore <pkgs>` | Comma-separated packages to skip |
| `--fix` | Remove malicious packages |
| `--yes, -y` | Auto-confirm --fix |
| `--version, -V` | Show version |

---

## Multi-Project Scanning

Scan multiple Node.js projects at once using `scan-all.js`.

### Scan a Directory

```bash
# Scan all projects in ~/Software
node scripts/scan-all.js ~/Software

# Limit search depth
node scripts/scan-all.js ~/code --depth 2

# Parallel scanning (faster for many projects)
node scripts/scan-all.js ~/projects --parallel
```

### Manage a Projects List

Build a reusable list of projects to scan regularly:

```bash
# Add all projects from a directory
node scripts/scan-all.js --add-all ~/Software

# Or add individual projects
node scripts/scan-all.js --add ~/projects/app-1
node scripts/scan-all.js --add ~/projects/app-2

# View your list
node scripts/scan-all.js --show-list

# Remove a project
node scripts/scan-all.js --remove ~/projects/old-app

# Scan from saved list
node scripts/scan-all.js --from-list
```

**List location priority:**
1. `./projects.json` (local, in current directory)
2. `~/.security-scan-projects.json` (global fallback)

### Example Output

```
🔍 Scanning projects from list...
Projects: 53

  ✓ Clean project-a
  ✓ Clean project-b
  ✗ 2 issues project-c (1 critical, 1 high)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  📊 SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Projects scanned:  53
  Clean:             52
  With issues:       1
  Packages scanned:  1518
```

---

## Configuration

Create a `.securityscanrc.json` file in your project root for persistent settings:

```json
{
  "ignore": ["package-to-skip"],
  "failOn": ["critical", "high"],
  "scanDeep": false,
  "analyzeScripts": false,
  "trustedPackages": ["@my-org/*"],
  "verbose": false,
  "strict": false
}
```

| Option | Type | Description |
|--------|------|-------------|
| `ignore` | `string[]` | Packages to skip during scan |
| `failOn` | `string[]` | Severity levels that cause exit code 1 |
| `scanDeep` | `boolean` | Scan transitive dependencies |
| `analyzeScripts` | `boolean` | Check postinstall scripts |
| `trustedPackages` | `string[]` | Glob patterns for trusted packages |
| `verbose` | `boolean` | Detailed output |
| `strict` | `boolean` | Fail on any risk level |

---

## What It Detects

- **137+ known malicious packages** — confirmed threats from npm advisories
- **5 major 2025 attack campaigns** — Shai-Hulud, PhantomRaven, Gluestack RAT, and more
- **Version-specific compromises** — only flags affected versions, not entire packages
- **Typosquatting variants** (66 packages) — common misspellings of popular packages
- **Credential theft packages** (25 packages) — packages designed to steal tokens and keys
- **Crypto mining malware** (13 packages) — hidden miners in dependencies
- **Suspicious postinstall scripts** — detects eval, network calls, obfuscation

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
      - run: npx @araptus/npm-security-scanner --deep --strict
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no issues found |
| `1` | Issues found — malicious packages detected |
| `2` | Error — configuration or runtime error |

Use in CI/CD:

```yaml
- run: node scripts/security-scan.js --json
  continue-on-error: false
```

---

## Web UI (Stakeholder Reports)

A browser-based interface for scanning dependencies — perfect for demos, stakeholder presentations, or non-technical team members.

### Quick Start

```bash
cd web
pnpm install
pnpm dev
```

Open [http://localhost:4321](http://localhost:4321) in your browser.

### Features

- **Drag & drop** — Upload `package.json` or lock files directly
- **Paste support** — Copy/paste file contents for quick scans
- **Deep scanning** — Automatically detects and parses lock files
- **Visual reports** — Color-coded severity levels, dependency chains
- **One-click remediation** — Copy removal commands for npm/pnpm/yarn
- **Campaign tracking** — See which attack campaigns affect your deps

### Build for Production

```bash
cd web
pnpm build
pnpm preview
```

The web UI is built with **Astro**, **React**, and **Tailwind CSS**. Deploys to Vercel out of the box.

---

## Threat Database

The threat database is at `security/compromised-packages.json`. It includes:

- `knownMalicious.confirmed` — packages confirmed as malicious
- `knownMalicious.typosquatting` — typosquatting variants
- `knownMalicious.credentialTheft` — token/credential stealers
- `knownMalicious.cryptoMalware` — crypto mining packages
- `campaigns` — coordinated attack campaigns with affected versions
- `trustedPackages` — allowlist of known-safe packages

### Update the Database

```bash
# Manual update
# Edit security/compromised-packages.json

# Or check for updates online
# (coming soon: --update flag)
```

---

## Project Structure

```
├── scripts/
│   ├── security-scan.js         # Main scanner CLI (zero dependencies)
│   └── scan-all.js              # Multi-project batch scanner
├── security/
│   ├── compromised-packages.json  # Threat database (137+ packages)
│   └── README.md                # Quick start guide
├── tests/
│   └── security-scan.test.js    # Unit tests
├── web/                         # Web UI (Astro + React + Tailwind)
│   ├── src/
│   │   ├── components/          # React components (Scanner.tsx)
│   │   ├── lib/                 # Scanner logic + threat DB
│   │   └── pages/               # Astro pages + API endpoints
│   └── package.json
├── .securityscanrc.json         # Your config (create from example)
├── projects.json                # Your projects list (for scan-all.js)
└── package.json
```

---

## Credits

- **Kris Araptus** — Original scanner and threat database
- **Jeremiah Coakley / FEDLIN** — Deep scanning

---

## License

MIT
