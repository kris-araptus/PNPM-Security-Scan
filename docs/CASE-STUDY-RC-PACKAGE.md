# Case Study: Detecting Compromised Transitive Dependencies

**Scanner Version:** PNPM-Security-Scan v2.0.0  
**Finding Severity:** 🔴 CRITICAL  
**Detection Method:** Deep Transitive Dependency Scan

---

## Overview

This case study demonstrates how deep transitive dependency scanning detected a **Confirmed Malicious** package (`rc@1.2.8`) that was hidden 5 levels deep in a project's dependency tree. The vulnerability would have been missed by standard dependency audits that only check direct dependencies.

---

## The Finding

### Vulnerability Summary

| Field | Value |
|-------|-------|
| **Package Name** | `rc` |
| **Installed Version** | 1.2.8 |
| **Classification** | Confirmed Malicious |
| **Dependency Type** | Transitive (indirect) |
| **Depth in Tree** | 5 levels |

### Dependency Chain

```
project@1.0.0
└─┬ vercel@25.2.3
  └─┬ update-notifier@5.1.0
    └─┬ latest-version@5.1.0
      └─┬ package-json@6.5.0
        ├─┬ registry-auth-token@4.2.2
        │ └── rc@1.2.8 ⚠️ COMPROMISED
        └─┬ registry-url@5.1.0
          └── rc@1.2.8 (deduped)
```

### Why Standard Audits Missed This

1. **Direct dependencies only** — `npm audit` and similar tools focus on direct dependencies
2. **No active CVE** — The `rc` package doesn't have a CVE assigned
3. **Author-based threat** — Compromise was due to author's demonstrated malicious intent, not a code vulnerability

---

## Background: The Marak Incident

In January 2022, developer Marak Squires intentionally sabotaged two of his popular npm packages (`colors` and `faker`) as a protest against corporations using open-source without compensation. The sabotage caused infinite loops that crashed applications.

### Why `rc` Is Flagged

While `rc` itself was not directly sabotaged, it is flagged as compromised because:

| Risk Factor | Description |
|-------------|-------------|
| **Author Trust Violated** | Same author demonstrated willingness to sabotage packages |
| **Abandoned** | No updates since npm suspended the author's account |
| **Supply Chain Risk** | Widely used as transitive dependency |
| **Configuration Parser** | Reads and parses config files — potential attack vector |

---

## Detection

### Scanner Output

```json
{
  "version": "2.0.0",
  "scanMode": "deep",
  "lockFile": "package-lock.json",
  "packagesScanned": {
    "total": 237,
    "direct": 3,
    "transitive": 234
  },
  "totalIssues": 1,
  "transitiveIssues": 1,
  "results": {
    "critical": [
      {
        "package": "rc",
        "version": "1.2.8",
        "isDirect": false,
        "isTransitive": true,
        "severity": "critical",
        "type": "Confirmed Malicious",
        "reason": "This package has been confirmed as malicious",
        "action": "REMOVE IMMEDIATELY"
      }
    ]
  }
}
```

### Key Detection Features Used

1. **`--deep` flag** — Enabled transitive dependency scanning via lock file parsing
2. **Lock file support** — Parsed `package-lock.json` to get full dependency tree
3. **Author-based threat database** — Flagged packages from known bad actors

---

## Remediation

### Solution: Update Parent Dependency

The compromised package was introduced through an outdated version of `vercel`. Updating to the latest version removed the vulnerable dependency chain entirely.

```bash
# Before
npm ls rc
└─┬ vercel@25.2.3
  └─┬ update-notifier@5.1.0
    └── ... → rc@1.2.8

# After update
npm install vercel@latest
npm ls rc
└── (empty)
```

### Alternative: NPM Overrides

If updating the parent package isn't possible, use npm overrides to replace the package:

```json
{
  "overrides": {
    "rc": "npm:@pnpm/rc@1.0.0"
  }
}
```

---

## Lessons Learned

### 1. Deep Scanning Is Essential

Standard security audits that only check direct dependencies miss threats like this. The `rc` package was **5 levels deep** in the dependency tree.

### 2. Author Trust Matters

Supply chain security isn't just about vulnerable code — it's about trusting the humans who maintain packages. The threat database should include:
- Packages with known malicious authors
- Abandoned packages from suspended accounts
- Packages associated with protest-ware incidents

### 3. Keep Dependencies Updated

The vulnerable dependency chain existed because `vercel@25.2.3` was outdated. The latest version (`50.0.1`) had already removed the problematic `update-notifier` dependency.

### 4. Lock Files Enable Deep Scanning

Without a lock file (`package-lock.json`, `pnpm-lock.yaml`, or `yarn.lock`), deep scanning cannot enumerate transitive dependencies. Always commit your lock files.

---

## Scan Commands Used

```bash
# Deep scan with verbose output
pnpm-security-scan --deep --verbose

# JSON output for CI/CD integration
pnpm-security-scan --deep --json

# Generate HTML report
pnpm-security-scan --deep --report
```

---

## Risk Assessment Template

Use this template for similar findings:

| Factor | Assessment | Notes |
|--------|------------|-------|
| **Active Exploitation** | Low/Medium/High | Known exploits in the wild? |
| **Data Exfiltration Risk** | Low/Medium/High | Does the package make network calls? |
| **Code Injection Risk** | Low/Medium/High | Does it eval or execute code? |
| **Supply Chain Integrity** | Intact/Compromised | Author trust status |
| **Remediation Difficulty** | Easy/Medium/Hard | Can parent be updated? |

---

## Timeline

| Date | Event |
|------|-------|
| 2022-01-07 | Marak sabotages colors and faker packages |
| 2022-01-09 | npm suspends Marak's account |
| 2022-01-10 | rc package flagged in threat databases |
| 2025-12 | PNPM-Security-Scan v2.0.0 detects rc in production project |
| 2025-12 | Remediated by updating parent dependency |

---

## References

- [The Marak Incident - Snyk Blog](https://snyk.io/blog/open-source-npm-packages-colors-faker/)
- [npm Security Best Practices](https://docs.npmjs.com/security-best-practices)
- [PNPM-Security-Scan Documentation](../README.md)

---

*This case study is provided to help organizations understand supply chain security risks and the importance of transitive dependency scanning.*

