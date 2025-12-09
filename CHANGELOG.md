# Changelog

All notable changes to the PNPM Security Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] - 2025-12-09

### 🚀 Major Release: Deep Scanning & Web UI

This release introduces **deep transitive dependency scanning** and a complete **web-based UI** for non-technical users. The threat database has been expanded and audited for accuracy.

### Added

#### Deep Scanning (CLI)
- **`--deep` / `-d` flag** - Scan all transitive dependencies from lock files
- **Lock file support** for:
  - `pnpm-lock.yaml` (pnpm)
  - `package-lock.json` (npm)  
  - `yarn.lock` (yarn)
- **Dependency chain tracking** - Shows how malicious packages entered your project
- **Transitive issue detection** - Identifies threats hidden in nested dependencies
- **New npm scripts**:
  - `security:scan:deep` - Deep scan with lock file analysis
  - `security:scan:deep:verbose` - Deep scan with detailed output
  - `security:scan:deep:strict` - Deep scan with strict mode
  - `security:audit` - Combined pnpm audit + deep scan
  - `security:full` - Full audit + outdated check + verbose deep scan

#### Web UI (`/web`)
- **Astro 5 + React 19 + Tailwind CSS 4** frontend
- **Drag & drop file upload** - Support for all file types
- **Paste support** - Paste file contents directly
- **Auto-detection** - Automatically identifies file type from content
- **Visual severity breakdown** - Clear threat categorization
- **Remediation guidance** - Step-by-step fix instructions
- **Copy-paste commands** - Ready-to-run uninstall commands
- **Responsive design** - Works on desktop and mobile
- **Vercel deployment** - Serverless API routes

#### Branding
- **Araptus branding** - Purple theme, logo, favicon
- **FEDLIN security badge** - Security solutions attribution
- **Professional UI/UX** - Modern, accessible design

### Changed

- **Threat database expanded** from 95 to **137 unique malicious packages**
- **CLI output** now shows unique package count (was showing duplicates)
- **Documentation** completely rewritten with:
  - Deep scanning guide
  - Web UI section
  - CI/CD integration examples
  - Complete CLI options table
  - Project structure diagram
- **Version bumped** from 1.1.0 to 2.0.0 (breaking: new output format)

### Fixed

- **Test assertions** updated to match actual CLI output format
- **Metadata accuracy** - Package counts now reflect unique threats
- **Font consistency** - Documentation matches actual implementation

### Technical Details

#### New Files
```
web/
├── src/
│   ├── components/
│   │   └── Scanner.tsx          # Main scanner component
│   ├── layouts/
│   │   └── Layout.astro         # Base layout with branding
│   ├── lib/
│   │   ├── scanner.ts           # Client-side scanning logic
│   │   ├── types.ts             # TypeScript interfaces
│   │   └── threat-db.json       # Synced threat database
│   ├── pages/
│   │   ├── api/
│   │   │   └── scan.ts          # Serverless API endpoint
│   │   └── index.astro          # Main landing page
│   └── styles/
│       └── global.css           # Tailwind + custom styles
├── public/
│   ├── araptus-logo.svg
│   ├── araptus-icon.png
│   ├── fedlin-logo.svg
│   └── favicon.ico
├── astro.config.mjs
├── package.json
├── tailwind.config.mjs
└── tsconfig.json
```

#### JSON Output Changes (Breaking)
The `--json` output format has changed:

**Before (1.x):**
```json
{
  "packagesScanned": 10
}
```

**After (2.0):**
```json
{
  "packagesScanned": {
    "total": 150,
    "direct": 20,
    "transitive": 130
  },
  "scanMode": "deep",
  "lockFile": "pnpm-lock.yaml",
  "transitiveIssues": 2
}
```

### Contributors

- **Kris Araptus** - Original scanner and threat database
- **Jeremiah Coakley / FEDLIN** - Deep scanning, web UI, documentation

---

## [1.1.0] - 2025-12-09

### Added
- Expanded threat database with new malicious packages
- Additional campaign tracking (PhantomRaven, Token Farming)
- Improved package categorization

### Changed
- Updated README with project rename to PNPM Security Scanner
- Enhanced malicious package detection

---

## [1.0.0] - 2025-12-09

### Added
- Initial release
- CLI scanner for npm/pnpm/yarn projects
- Threat database with 42+ known malicious packages
- Shai-Hulud campaign detection
- Typosquatting protection
- Trusted package whitelisting
- JSON output for CI/CD
- Verbose and strict modes

---

## Migration Guide: 1.x → 2.0

### Breaking Changes

1. **JSON output structure changed** - If you parse `--json` output, update your scripts to handle the new `packagesScanned` object format.

2. **New exit behavior with `--deep`** - Deep scans may find issues in transitive dependencies that weren't previously detected.

### Recommended Actions

1. **Update CI/CD pipelines** to use `--deep` for comprehensive scanning:
   ```yaml
   - run: npx @kris-araptus/npm-security-scanner --deep --strict
   ```

2. **Generate lock files** if you don't have them:
   ```bash
   pnpm install  # Creates pnpm-lock.yaml
   npm install   # Creates package-lock.json
   yarn install  # Creates yarn.lock
   ```

3. **Review transitive dependencies** - Run `--deep --verbose` to see the full dependency tree analysis.

---

[2.0.0]: https://github.com/kris-araptus/pnpm-security-scan/compare/v1.1.0...v2.0.0
[1.1.0]: https://github.com/kris-araptus/pnpm-security-scan/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/kris-araptus/pnpm-security-scan/releases/tag/v1.0.0

