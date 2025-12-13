# Changelog

All notable changes to the PNPM Security Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] - 2025-12-13

### 🚀 Major Release: Deep Scanning, Enhanced Web UI & Multi-Project Support

This release introduces **deep transitive dependency scanning**, a significantly enhanced **web-based UI** with real-time scanning visualization, and **multi-project batch scanning**. The threat database tracks 5 major 2025 attack campaigns.

---

### Added

#### Deep Scanning (CLI) — *Originally by Kris*
- **`--deep` / `-d` flag** — Scan all transitive dependencies from lock files
- **Lock file support** for:
  - `pnpm-lock.yaml` (pnpm)
  - `package-lock.json` (npm)  
  - `yarn.lock` (yarn)
- **Dependency chain tracking** — Shows how malicious packages entered your project
- **Transitive issue detection** — Identifies threats hidden in nested dependencies

#### Multi-Project Scanning — *Originally by Kris*
- **`scan-all.js`** — Scan entire directories of projects at once
- **Projects list management** — `--add`, `--remove`, `--from-list`, `--show-list`
- **Parallel scanning** — `--parallel` flag for faster batch scans
- **Configurable depth** — `--depth` flag to control search depth

#### New CLI Features — *Originally by Kris*
- **`--fix`** — Auto-remove detected malicious packages
- **`--report`** — Generate HTML security reports
- **`--analyze-scripts`** — Check postinstall scripts for suspicious patterns
- **`--ignore <packages>`** — Skip specific packages during scan
- **`--silent`** — Suppress output (exit code only)
- **`--config <path>`** — Use custom config file
- **`.securityscanrc.json`** — Persistent project configuration

#### Web UI (`/web`) — *Originally by Kris, Enhanced by FEDLIN*

**Base Web UI (Kris):**
- **Astro 5 + React 19 + Tailwind CSS 4** frontend
- **Drag & drop file upload** — Support for all file types
- **Paste support** — Paste file contents directly
- **Auto-detection** — Automatically identifies file type from content
- **Vercel deployment** — Serverless API routes
- **Araptus branding** — Purple theme, logo, favicon

**Enhanced Visualization (FEDLIN):**
- **Animated multi-stage scan progress** — Visual parsing → analyzing → checking → finalizing stages
- **Multi-ring spinner** with staggered counter-rotating animations
- **Real-time package counter** — Shows packages found during scan
- **Scanning line effect** — Animated sweep lines during analysis
- **Copy-to-clipboard commands** — One-click copy for npm/pnpm/yarn removal commands
- **Expandable issue cards** — Click to reveal affected versions and campaign details
- **Version badge** — Shows v2.0.0 with "Deep Scan Enabled" indicator

**Improved Results Display (FEDLIN):**
- **Enhanced stat cards** with icons and gradient backgrounds
- **Severity breakdown grid** with hover effects
- **Transitive dependency chain visualization** with arrow indicators
- **Remediation guidance cards** for critical, typosquatting, and transitive issues
- **Success celebration** — Animated shield and bounce effect for clean scans

**Campaign Timeline (FEDLIN):**
- **5 attack campaigns** with detailed cards and timeline view:
  - 🐛 Shai-Hulud (700+ packages, Sept-Nov 2025)
  - 🎣 Credential Phishing (eslint-prettier ecosystem, July 2025)
  - 🖥️ Gluestack RAT (17 @react-native-aria packages, June 2025)
  - 🦅 PhantomRaven (126 packages, Aug 2025)
  - 🎭 Token Farming (150K+ fake packages, Nov 2025)
- **Affected package tags** shown per campaign
- **Color-coded severity indicators**

**New CLI Features Section (FEDLIN):**
- Visual showcase of new v2.0.0 CLI capabilities
- Code examples for each feature
- Icons for quick scanning

---

### Changed

- **Threat database expanded** to **137 unique malicious packages** across 5 campaigns
- **Version indicator** now prominently displayed with database update date
- **Scanner.tsx** completely rewritten with enhanced UX (464 → 646 lines)
- **global.css** expanded with new animations and effects (283 → 400+ lines)
- **index.astro** enhanced with campaign timeline and feature showcase
- **CLI output** now shows ignored/trusted package counts

### Fixed

- **Test assertions** updated to match CLI output format
- **README.md** duplicate Project Structure section removed
- **Merge conflicts** from Kris's 1.2.1 release resolved with local 2.0.0 progress preserved

---

### Technical Details

#### New/Enhanced Files
```
web/src/
├── components/
│   └── Scanner.tsx          # 🔄 Enhanced: Animated stages, copy commands, expandable cards
├── pages/
│   └── index.astro          # 🔄 Enhanced: Campaign timeline, CLI features, version badge
├── styles/
│   └── global.css           # 🔄 Enhanced: Animations, progress bars, accessibility
└── lib/
    └── threat-db.json       # 🔄 Synced with latest 137 threats
```

#### New CSS Animations
- `@keyframes scanLine` — Vertical sweep during scanning
- `@keyframes dataFlow` — Background grid animation
- `@keyframes fadeIn` — Smooth content transitions
- `@keyframes slideUp` — Entry animations
- `.scanning-lines` — Matrix-style scan effect
- `.progress-bar-fill::after` — Shimmer effect on progress

#### JSON Output (Breaking from 1.x)
```json
{
  "version": "2.0.0",
  "scanMode": "deep",
  "lockFile": "pnpm-lock.yaml",
  "packagesScanned": {
    "total": 150,
    "direct": 20,
    "transitive": 130
  },
  "packagesIgnored": 2,
  "packagesTrusted": 15,
  "totalIssues": 3,
  "transitiveIssues": 2,
  "results": { "critical": [], "high": [], "medium": [], "low": [] },
  "suspiciousScripts": []
}
```

---

### Contributors

- **Kris Araptus** — Original scanner, threat database, deep scanning, multi-project scanner, CLI features
- **Jeremiah Coakley / FEDLIN** — Web UI visualization enhancements, campaign timeline, animated progress, copy commands

---

## [1.2.1] - 2025-12-10

### Added
- Package name changed to `@araptus/npm-security-scanner`
- New bin entries for global CLI usage
- Additional scan scripts

### Changed  
- Updated repository URLs
- Upgraded @types/node to 25.0.1

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

1. **JSON output structure changed** — If you parse `--json` output, update your scripts to handle the new `packagesScanned` object format.

2. **New exit behavior with `--deep`** — Deep scans may find issues in transitive dependencies that weren't previously detected.

3. **Package name changed** — Now published as `@araptus/npm-security-scanner`

### Recommended Actions

1. **Update CI/CD pipelines** to use `--deep` for comprehensive scanning:
   ```yaml
   - run: npx @araptus/npm-security-scanner --deep --strict
   ```

2. **Generate lock files** if you don't have them:
   ```bash
   pnpm install  # Creates pnpm-lock.yaml
   npm install   # Creates package-lock.json
   yarn install  # Creates yarn.lock
   ```

3. **Review transitive dependencies** — Run `--deep --verbose` to see the full dependency tree analysis.

4. **Try the Web UI** — Visit [security-scanner.araptus.com](https://security-scanner.araptus.com) for visual scanning.

---

[2.0.0]: https://github.com/araptus/npm-security-scanner/compare/v1.2.1...v2.0.0
[1.2.1]: https://github.com/araptus/npm-security-scanner/compare/v1.1.0...v1.2.1
[1.1.0]: https://github.com/araptus/npm-security-scanner/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/araptus/npm-security-scanner/releases/tag/v1.0.0
