# Case Study: Protest-Ware Supply Chain Attack (node-ipc)

**Scanner Version:** PNPM-Security-Scan v2.0.0  
**Finding Severity:** 🔴 CRITICAL  
**Detection Method:** Deep Transitive Dependency Scan + Known Malicious Database

---

## Overview

This case study documents the detection and remediation of **protest-ware** — intentionally malicious code inserted into legitimate packages as a form of political protest. The `node-ipc` package and its associated `peacenotwar` dependency were compromised in March 2022, affecting millions of downstream projects including major frameworks like Vue.js CLI.

---

## The Finding

### Vulnerability Summary

| Field | Value |
|-------|-------|
| **Package Name** | `node-ipc` |
| **Affected Versions** | 10.1.1, 10.1.2, 10.1.3, 11.x |
| **Classification** | Confirmed Malicious (Protest-Ware) |
| **CVE** | CVE-2022-23812 |
| **CVSS Score** | 9.8 (Critical) |
| **Associated Package** | `peacenotwar` |

### Dependency Chain (Example Project)

```
project@1.0.0
└─┬ @vue/cli@5.0.0
  └─┬ @vue/cli-shared-utils@5.0.0
    └─┬ node-ipc@10.1.1 ⚠️ PROTEST-WARE
      └── peacenotwar@9.1.6 ⚠️ ASSOCIATED
```

### Why This Is Critical

1. **Intentional data destruction** — Certain versions replaced file contents with heart emojis
2. **Geolocation targeting** — Destructive payload activated based on IP geolocation
3. **Legitimate package hijacked** — 1M+ weekly downloads before incident
4. **Wide blast radius** — Affected Vue CLI, Unity Hub, and other major projects

---

## Background: The node-ipc Incident

### Timeline

| Date | Event |
|------|-------|
| 2022-03-07 | Maintainer RIAEvangelist publishes `peacenotwar` package |
| 2022-03-08 | `node-ipc@10.1.1` released with `peacenotwar` as dependency |
| 2022-03-15 | `node-ipc@10.1.1` found to contain file-wiping code |
| 2022-03-16 | GitHub Advisory published (CVE-2022-23812) |
| 2022-03-16 | Malicious versions unpublished from npm |
| 2022-03-17 | Major frameworks issue emergency patches |

### Malicious Behavior

The compromised versions contained two distinct threats:

#### 1. `peacenotwar` Module (All Affected Versions)
```
- Creates file: WITH-LOVE-FROM-AMERICA.txt
- Displays anti-war message to console
- Low severity on its own
```

#### 2. File Corruption (10.1.1 specifically)
```
- Triggered for users with Russian/Belarusian IP addresses
- Replaced file contents with ❤️ emoji
- Targeted files in Desktop, Documents, and project directories
- Destructive and irreversible
```

---

## Detection

### Scanner Output

```json
{
  "version": "2.0.0",
  "scanMode": "deep",
  "lockFile": "pnpm-lock.yaml",
  "packagesScanned": {
    "total": 412,
    "direct": 8,
    "transitive": 404
  },
  "totalIssues": 2,
  "transitiveIssues": 2,
  "results": {
    "critical": [
      {
        "package": "node-ipc",
        "version": "10.1.1",
        "isDirect": false,
        "isTransitive": true,
        "severity": "critical",
        "type": "Confirmed Malicious",
        "reason": "This package has been confirmed as malicious",
        "action": "REMOVE IMMEDIATELY",
        "dependencyChain": ["@vue/cli", "@vue/cli-shared-utils", "node-ipc"]
      },
      {
        "package": "peacenotwar",
        "version": "9.1.6",
        "isDirect": false,
        "isTransitive": true,
        "severity": "critical",
        "type": "Confirmed Malicious",
        "reason": "This package has been confirmed as malicious",
        "action": "REMOVE IMMEDIATELY",
        "dependencyChain": ["@vue/cli", "@vue/cli-shared-utils", "node-ipc", "peacenotwar"]
      }
    ]
  }
}
```

### CLI Output

```
🔬 Scan mode: DEEP SCAN (via pnpm-lock.yaml)
📦 Packages scanned: 412
   ├─ Direct dependencies: 8
   └─ Transitive dependencies: 404

🚨 CRITICAL ISSUES (2)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ❌ TRANSITIVE node-ipc@10.1.1
     Type: Confirmed Malicious
     Reason: This package has been confirmed as malicious
     Action: REMOVE IMMEDIATELY
     Dependency chain: @vue/cli → @vue/cli-shared-utils → node-ipc

  ❌ TRANSITIVE peacenotwar@9.1.6
     Type: Confirmed Malicious
     Reason: This package has been confirmed as malicious
     Action: REMOVE IMMEDIATELY
     Dependency chain: @vue/cli → @vue/cli-shared-utils → node-ipc → peacenotwar

❌ Security scan FAILED - Critical/High severity issues found!
```

---

## Remediation

### Solution 1: Update Parent Dependency (Recommended)

The affected package was introduced through an outdated framework CLI. Updating to patched versions removes the threat:

```bash
# Check current version
npm ls node-ipc

# Update to patched version
npm install @vue/cli@latest

# Verify removal
npm ls node-ipc
# Should show: (empty) or safe version
```

### Solution 2: NPM Overrides (Lock to Safe Version)

Force a safe version if immediate updates aren't possible:

```json
{
  "overrides": {
    "node-ipc": "9.2.1"
  }
}
```

For pnpm, use `pnpm.overrides`:

```json
{
  "pnpm": {
    "overrides": {
      "node-ipc": "9.2.1"
    }
  }
}
```

### Solution 3: Remove and Replace

If the parent package can be removed entirely:

```bash
# Remove the vulnerable chain
npm uninstall @vue/cli-shared-utils

# Find alternative packages
npm search ipc
```

---

## Impact Assessment

### Affected Ecosystem

| Package | Weekly Downloads | Impact |
|---------|-----------------|--------|
| `node-ipc` | 1,000,000+ | Direct |
| `@vue/cli` | 500,000+ | Transitive |
| Unity Hub | Unknown | Production systems |
| Various CI/CD | Unknown | Build pipelines |

### Risk Factors

| Factor | Assessment | Notes |
|--------|------------|-------|
| **Active Exploitation** | Confirmed | Geolocation-triggered file destruction |
| **Data Exfiltration Risk** | Low | No data sent externally |
| **Code Injection Risk** | N/A | Not the attack vector |
| **Data Destruction Risk** | Critical | Files overwritten with emojis |
| **Remediation Difficulty** | Easy | Update parent or override version |

---

## Lessons Learned

### 1. Maintainer Trust Is Critical

The `node-ipc` maintainer had a 10+ year history of legitimate contributions. This incident demonstrated that even trusted maintainers can introduce malicious code, and past behavior doesn't guarantee future trustworthiness.

### 2. Protest-Ware Is a Real Threat

Unlike traditional malware aimed at profit, protest-ware is motivated by political or ideological goals. This makes it unpredictable — maintainers may feel justified in their actions.

### 3. Lock Files Save You

Projects with committed lock files could audit exactly which version of `node-ipc` was installed. Projects without lock files may have pulled the malicious version unknowingly.

### 4. Deep Scanning Is Non-Negotiable

The threat was **4 levels deep** in the dependency tree:
```
project → @vue/cli → @vue/cli-shared-utils → node-ipc → peacenotwar
```

Standard `npm audit` at the time did not flag this immediately.

### 5. Geolocation Targeting Is Sophisticated

The attack specifically targeted users based on IP geolocation. This adds a layer of complexity where:
- CI/CD systems in certain regions would be affected
- Local development might be safe while production is vulnerable
- Testing in one region doesn't guarantee safety in another

---

## Threat Database Entry

The following entries in `compromised-packages.json` detect this threat:

```json
{
  "knownMalicious": {
    "confirmed": [
      "node-ipc",
      "peacenotwar"
    ]
  }
}
```

---

## Prevention Strategies

### For Organizations

1. **Enable deep scanning in CI/CD**
   ```yaml
   - run: npx @araptus/npm-security-scanner --deep --strict
   ```

2. **Pin major dependencies**
   ```json
   {
     "@vue/cli": "5.0.8"
   }
   ```

3. **Use npm audit with --audit-level**
   ```bash
   npm audit --audit-level=critical
   ```

4. **Monitor for maintainer activity**
   - Watch for sudden version bumps
   - Track maintainer account changes
   - Subscribe to security advisories

### For Open Source Maintainers

1. **Multi-maintainer governance** — No single point of failure
2. **Signed commits** — Verify code authorship
3. **Automated security scanning** — Catch issues before publish
4. **Responsible disclosure** — Report issues, don't retaliate

---

## References

- [CVE-2022-23812 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-23812)
- [Snyk: Peacenotwar and node-ipc](https://snyk.io/blog/peacenotwar-malicious-npm-node-ipc-package-vulnerability/)
- [The Register: npm libraries corrupted with protestware](https://www.theregister.com/2022/03/18/node_ipc_protestware/)
- [GitHub Advisory Database](https://github.com/advisories/GHSA-97m3-w2cp-4xx6)
- [PNPM-Security-Scan Documentation](../README.md)

---

## Related Incidents

| Package | Date | Type | Impact |
|---------|------|------|--------|
| `colors` | 2022-01 | Protest-ware | Infinite loop |
| `faker` | 2022-01 | Protest-ware | Deleted codebase |
| `node-ipc` | 2022-03 | Protest-ware | File corruption |
| `es5-ext` | 2022-03 | Protest-ware | Console messages |

---

*This case study documents a real supply chain security incident. Package names and CVE references are public information. The dependency chains shown are representative examples, not from any specific organization.*

