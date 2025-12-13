# PNPM Security Scanner - Roadmap

Feature roadmap with implementation checklists.

---

## Phase 1: Core Improvements (High Impact)

### 1.1 Lock File Scanning + Version Matching

**Priority:** 🔴 Critical  
**Effort:** Medium  
**Status:** ✅ Complete

Scan actual installed versions from lock files instead of just package.json ranges. Match against version-specific compromises in campaigns.

**Checklist:**
- [x] Parse `pnpm-lock.yaml` format
- [x] Parse `package-lock.json` format  
- [ ] Parse `yarn.lock` format (basic support only)
- [x] Extract exact versions from lock files
- [x] Match versions against `affectedVersions` in campaigns
- [x] Fall back to package.json if no lock file found
- [x] Add tests for lock file parsing
- [x] Update documentation

**Files to modify:**
- `scripts/security-scan.js`
- `tests/security-scan.test.js`

---

### 1.2 Configuration File Support

**Priority:** 🟡 High  
**Effort:** Low  
**Status:** ✅ Complete

Support `.securityscanrc.json` for project-specific settings.

**Checklist:**
- [x] Define config file schema
- [x] Search for config in project root
- [x] Support `ignore` array for packages to skip
- [x] Support `failOn` array for severity levels
- [ ] Support `customDatabase` path
- [x] Support `trustedPackages` additions
- [x] Merge config with CLI flags (CLI takes precedence)
- [x] Add `--config` flag to specify custom config path
- [x] Document config options in README

**Config schema:**
```json
{
  "ignore": ["package-to-skip"],
  "failOn": ["critical", "high"],
  "customDatabase": "./custom-threats.json",
  "trustedPackages": ["@my-org/*"],
  "scanLockFile": true,
  "scanTransitive": false
}
```

---

### 1.3 Auto-Update Database

**Priority:** 🟡 High  
**Effort:** Medium  
**Status:** 🔲 Not Started

Fetch latest threat database from a hosted source.

**Checklist:**
- [ ] Host database on GitHub raw URL
- [ ] Add `--update` flag to fetch latest
- [ ] Check database age and warn if > 7 days old
- [ ] Add `--offline` flag to skip update check
- [ ] Backup local database before updating
- [ ] Verify downloaded JSON is valid
- [ ] Show diff of what changed
- [ ] Add tests for update functionality
- [ ] Document update process

---

## Phase 2: Quick Wins (Low Effort)

### 2.1 --version Flag

**Priority:** 🟢 Low  
**Effort:** 5 min  
**Status:** ✅ Complete

**Checklist:**
- [x] Add `--version` and `-V` flags
- [x] Read version from package.json
- [x] Print version and exit

---

### 2.2 --ignore Flag

**Priority:** 🟡 High  
**Effort:** 20 min  
**Status:** ✅ Complete

**Checklist:**
- [x] Add `--ignore <packages>` flag
- [x] Accept comma-separated package names
- [x] Skip ignored packages during scan
- [x] Show ignored count in results
- [x] Add tests

---

### 2.3 --fix Flag

**Priority:** 🟡 High  
**Effort:** 30 min  
**Status:** ✅ Complete

**Checklist:**
- [x] Add `--fix` flag
- [x] Prompt before removing packages (unless --yes)
- [x] Run `pnpm remove` / `npm uninstall` for malicious packages
- [x] Show what was removed
- [x] Add `--yes` flag to skip confirmation

---

### 2.4 --silent Flag

**Priority:** 🟢 Low  
**Effort:** 10 min  
**Status:** ✅ Complete

**Checklist:**
- [x] Add `--silent` and `-s` flags
- [x] Suppress all output except errors
- [x] Still return correct exit codes

---

### 2.5 Colorized Summary

**Priority:** 🟢 Low  
**Effort:** 15 min  
**Status:** ✅ Complete

**Checklist:**
- [x] Add color to package counts by severity
- [ ] Add progress indicator for large scans
- [x] Respect `NO_COLOR` environment variable

---

## Phase 3: Advanced Features (Medium Effort)

### 3.1 Transitive Dependency Scanning

**Priority:** 🔴 Critical  
**Effort:** High  
**Status:** ✅ Complete

Scan entire dependency tree, not just direct dependencies.

**Checklist:**
- [x] Add `--deep` flag for transitive scanning
- [x] Parse node_modules structure
- [x] Handle circular dependencies
- [ ] Show dependency path for issues (A → B → malicious-pkg)
- [ ] Add performance optimizations (caching)
- [x] Document deep scanning mode

---

### 3.2 Postinstall Script Analysis

**Priority:** 🟡 High  
**Effort:** Medium  
**Status:** ✅ Complete

Analyze package scripts for suspicious patterns.

**Checklist:**
- [x] Add `--analyze-scripts` flag
- [x] Read package.json from node_modules
- [x] Check postinstall, preinstall, install scripts
- [x] Match against indicator patterns from database
- [x] Report suspicious patterns found
- [x] Document script analysis

---

### 3.3 HTML Report Generation

**Priority:** 🟢 Medium  
**Effort:** Medium  
**Status:** ✅ Complete

Generate pretty HTML reports for stakeholders.

**Checklist:**
- [x] Add `--report` flag
- [x] Add `--report-path` to specify output
- [x] Create HTML template with styling
- [x] Include summary statistics
- [x] List all issues with details
- [x] Show recommendations
- [x] Include scan metadata (date, version, etc.)
- [x] Make report self-contained (inline CSS)

---

### 3.4 Remediation Suggestions

**Priority:** 🟡 High  
**Effort:** Medium  
**Status:** 🔲 Not Started

Suggest safe alternatives for malicious packages.

**Checklist:**
- [ ] Add `alternatives` field to database entries
- [ ] Add `safeVersions` field for version-specific issues
- [ ] Display alternatives in scan output
- [ ] Display safe versions to downgrade to
- [ ] Add `--suggest` flag to show extra detail
- [ ] Populate alternatives for top 20 malicious packages
- [ ] Add tests

---

## Phase 4: Distribution (High Effort)

### 4.1 Publish to npm

**Priority:** 🔴 Critical  
**Effort:** Medium  
**Status:** 🔲 Not Started

**Checklist:**
- [ ] Set up npm account/org
- [ ] Configure package.json for publishing
- [ ] Add proper bin entry
- [ ] Test global installation
- [ ] Test npx usage
- [ ] Write installation docs
- [ ] Set up CI/CD for publishing
- [ ] Add changelog

---

### 4.2 GitHub Action

**Priority:** 🟡 High  
**Effort:** Medium  
**Status:** 🔲 Not Started

**Checklist:**
- [ ] Create action.yml
- [ ] Define inputs (fail-on, ignore, etc.)
- [ ] Define outputs (issues-found, report-path)
- [ ] Create Dockerfile or composite action
- [ ] Test in sample workflow
- [ ] Publish to GitHub Marketplace
- [ ] Document usage in README

---

### 4.3 Real-time Advisory Integration

**Priority:** 🟢 Medium  
**Effort:** High  
**Status:** 🔲 Not Started

**Checklist:**
- [ ] Integrate GitHub Advisory Database API
- [ ] Integrate npm audit API
- [ ] Cache API responses
- [ ] Merge with local database
- [ ] Handle rate limiting
- [ ] Add `--live` flag for real-time checks
- [ ] Add tests with mocked APIs

---

## Phase 5: Code Quality

### 5.1 TypeScript Rewrite

**Priority:** 🟢 Low  
**Effort:** High  
**Status:** 🔲 Not Started

**Checklist:**
- [ ] Set up TypeScript configuration
- [ ] Define types for database schema
- [ ] Define types for scan results
- [ ] Convert security-scan.js to TypeScript
- [ ] Add build step
- [ ] Update tests
- [ ] Update documentation

---

## Implementation Order

| Phase | Feature | Priority | Effort | Order |
|-------|---------|----------|--------|-------|
| 2.1 | --version flag | Low | 5 min | 1 |
| 2.4 | --silent flag | Low | 10 min | 2 |
| 2.5 | Colorized summary | Low | 15 min | 3 |
| 2.2 | --ignore flag | High | 20 min | 4 |
| 2.3 | --fix flag | High | 30 min | 5 |
| 1.2 | Config file | High | Low | 6 |
| 1.1 | Lock file scanning | Critical | Medium | 7 |
| 1.3 | Auto-update | High | Medium | 8 |
| 3.1 | Transitive scanning | Critical | High | 9 |
| 3.2 | Script analysis | High | Medium | 10 |
| 3.4 | Remediation | High | Medium | 11 |
| 3.3 | HTML reports | Medium | Medium | 12 |
| 4.1 | npm publish | Critical | Medium | 13 |
| 4.2 | GitHub Action | High | Medium | 14 |
| 4.3 | Live advisories | Medium | High | 15 |
| 5.1 | TypeScript | Low | High | 16 |

---

## Progress Tracking

**Last Updated:** December 10, 2025

| Feature | Status | Notes |
|---------|--------|-------|
| Lock file scanning | ✅ | pnpm-lock.yaml & package-lock.json |
| Version matching | ✅ | Matches against affectedVersions |
| Config file | ✅ | .securityscanrc.json support |
| --version flag | ✅ | -V and --version |
| --ignore flag | ✅ | --ignore pkg1,pkg2 |
| --fix flag | ✅ | --fix with --yes confirmation |
| --silent flag | ✅ | -s and --silent |
| Auto-update | 🔲 | Needs remote hosting |
| Transitive scanning | ✅ | --deep flag |
| Script analysis | ✅ | --analyze-scripts flag |
| HTML reports | ✅ | --report flag |
| Multi-project scan | ✅ | scan-all.js |
| Remediation | 🔲 | - |
| npm publish | 🔲 | - |
| GitHub Action | 🔲 | - |

**Legend:** 🔲 Not Started | 🟡 In Progress | ✅ Complete

