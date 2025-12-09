#!/usr/bin/env node

/**
 * npm Security Scanner
 * 
 * Detects compromised npm packages in Node.js projects by scanning
 * dependencies against a configurable JSON threat database.
 * 
 * Built in response to the Shai-Hulud malware campaign (Sept 2025)
 * and other major supply chain attacks.
 * 
 * Usage:
 *   node scripts/security-scan.js [options]
 * 
 * Options:
 *   --verbose, -v    Show detailed output for each package
 *   --json           Output results in JSON format
 *   --strict         Fail on any risk level (not just critical/high)
 *   --deep, -d       Deep scan: analyze lock files for transitive dependencies
 *   --help, -h       Show help
 * 
 * Exit Codes:
 *   0 - No issues found
 *   1 - Critical/High severity issues found
 *   2 - Configuration or runtime error
 * 
 * @version 2.0.0
 * @author Kris Araptus
 * @contributor Jeremiah Coakley (FEDLIN) - Lock file scanning
 * @license MIT
 */

const fs = require('fs');
const path = require('path');

// ANSI color codes for terminal output
const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgYellow: '\x1b[43m',
  bgBlue: '\x1b[44m',
};

// Parse command line arguments
const args = process.argv.slice(2);
const options = {
  verbose: args.includes('--verbose') || args.includes('-v'),
  json: args.includes('--json'),
  strict: args.includes('--strict'),
  deep: args.includes('--deep') || args.includes('-d'),
  help: args.includes('--help') || args.includes('-h'),
};

/**
 * Display help information
 */
function showHelp() {
  console.log(`
${colors.bold}npm Security Scanner${colors.reset}
${colors.dim}Detect compromised npm packages in your project${colors.reset}

${colors.bold}Usage:${colors.reset}
  node scripts/security-scan.js [options]
  pnpm run security:scan [-- options]

${colors.bold}Options:${colors.reset}
  --verbose, -v    Show detailed output for each package scanned
  --json           Output results in JSON format (for CI/CD)
  --strict         Fail on any risk level, not just critical/high
  --deep, -d       Deep scan: analyze lock files for transitive dependencies
  --help, -h       Show this help message

${colors.bold}Examples:${colors.reset}
  ${colors.cyan}pnpm run security:scan${colors.reset}              Quick scan (direct deps only)
  ${colors.cyan}pnpm run security:scan --deep${colors.reset}       Deep scan (all transitive deps)
  ${colors.cyan}pnpm run security:scan:verbose${colors.reset}      Detailed scan
  ${colors.cyan}pnpm run security:scan -- --json${colors.reset}    JSON output

${colors.bold}Lock File Support:${colors.reset}
  ${colors.dim}With --deep, scans transitive dependencies from:${colors.reset}
  • pnpm-lock.yaml  (pnpm)
  • package-lock.json (npm)
  • yarn.lock (yarn)

${colors.bold}Exit Codes:${colors.reset}
  ${colors.green}0${colors.reset} - All clear, no issues found
  ${colors.red}1${colors.reset} - Critical/High severity issues detected
  ${colors.yellow}2${colors.reset} - Configuration or runtime error

${colors.bold}Documentation:${colors.reset}
  ${colors.dim}docs/SECURITY-SCANNER.md${colors.reset}       Complete guide
  ${colors.dim}security/README.md${colors.reset}             Quick start
`);
  process.exit(0);
}

if (options.help) {
  showHelp();
}

/**
 * Find the project root by looking for package.json
 * @returns {string} Path to project root
 */
function findProjectRoot() {
  let currentDir = process.cwd();
  
  while (currentDir !== path.parse(currentDir).root) {
    if (fs.existsSync(path.join(currentDir, 'package.json'))) {
      return currentDir;
    }
    currentDir = path.dirname(currentDir);
  }
  
  return process.cwd();
}

/**
 * Find the security database file
 * @returns {string|null} Path to compromised-packages.json or null
 */
function findSecurityDatabase() {
  const projectRoot = findProjectRoot();
  
  // Check multiple possible locations
  const possiblePaths = [
    path.join(projectRoot, 'security', 'compromised-packages.json'),
    path.join(projectRoot, 'compromised-packages.json'),
    path.join(__dirname, '..', 'security', 'compromised-packages.json'),
    path.join(__dirname, 'compromised-packages.json'),
  ];
  
  for (const p of possiblePaths) {
    if (fs.existsSync(p)) {
      return p;
    }
  }
  
  return null;
}

/**
 * Load the compromised packages database
 * @returns {Object|null} Database object or null on error
 */
function loadCompromisedDb() {
  const dbPath = findSecurityDatabase();
  
  if (!dbPath) {
    console.error(`${colors.red}✗ Error: Could not find compromised-packages.json${colors.reset}`);
    console.error(`${colors.dim}  Looked in: security/, project root, and script directory${colors.reset}`);
    return null;
  }
  
  try {
    const content = fs.readFileSync(dbPath, 'utf8');
    const db = JSON.parse(content);
    
    if (options.verbose && !options.json) {
      console.log(`${colors.dim}Database loaded from: ${dbPath}${colors.reset}`);
    }
    
    return db;
  } catch (error) {
    console.error(`${colors.red}✗ Error loading database: ${error.message}${colors.reset}`);
    return null;
  }
}

/**
 * Load the project's package.json
 * @returns {Object|null} Package.json contents or null
 */
function loadPackageJson() {
  const projectRoot = findProjectRoot();
  const packagePath = path.join(projectRoot, 'package.json');
  
  if (!fs.existsSync(packagePath)) {
    console.error(`${colors.red}✗ Error: No package.json found in ${projectRoot}${colors.reset}`);
    return null;
  }
  
  try {
    const content = fs.readFileSync(packagePath, 'utf8');
    return JSON.parse(content);
  } catch (error) {
    console.error(`${colors.red}✗ Error reading package.json: ${error.message}${colors.reset}`);
    return null;
  }
}

// ============================================
// LOCK FILE PARSING (Deep Scan Support)
// ============================================

/**
 * Detect which lock file exists in the project
 * @returns {Object|null} Lock file info { type, path } or null
 */
function detectLockFile() {
  const projectRoot = findProjectRoot();
  
  const lockFiles = [
    { type: 'pnpm', filename: 'pnpm-lock.yaml' },
    { type: 'npm', filename: 'package-lock.json' },
    { type: 'yarn', filename: 'yarn.lock' },
  ];
  
  for (const lock of lockFiles) {
    const lockPath = path.join(projectRoot, lock.filename);
    if (fs.existsSync(lockPath)) {
      return { type: lock.type, path: lockPath, filename: lock.filename };
    }
  }
  
  return null;
}

/**
 * Parse pnpm-lock.yaml without external YAML library
 * Extracts package names and versions from the lockfile
 * @param {string} content - Raw YAML content
 * @returns {Map<string, Object>} Map of package name to { version, dependencyChain }
 */
function parsePnpmLock(content) {
  const packages = new Map();
  const lines = content.split('\n');
  
  let inPackages = false;
  let currentPackage = null;
  let currentVersion = null;
  let indent = 0;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    
    // Skip empty lines and comments
    if (!trimmed || trimmed.startsWith('#')) continue;
    
    // Detect packages section (pnpm v6+ format)
    if (trimmed === 'packages:') {
      inPackages = true;
      continue;
    }
    
    // Exit packages section
    if (inPackages && !line.startsWith(' ') && !line.startsWith('\t') && trimmed !== '') {
      if (!trimmed.startsWith('/') && !trimmed.startsWith("'")) {
        inPackages = false;
        continue;
      }
    }
    
    if (inPackages) {
      // Match package entries like: /@scope/package@version: or /package@version:
      // pnpm v9+ format: '@scope/package@version':
      const packageMatch = trimmed.match(/^['"]?\/?((?:@[^@/]+\/)?[^@:]+)@([^:']+)['"]?:?\s*$/);
      
      if (packageMatch) {
        const [, name, version] = packageMatch;
        currentPackage = name;
        currentVersion = version.replace(/['"]/g, '');
        
        if (!packages.has(currentPackage)) {
          packages.set(currentPackage, {
            version: currentVersion,
            isTransitive: true,
            dependencyChain: [],
          });
        }
      }
      
      // Also handle the snapshots section format
      const snapshotMatch = trimmed.match(/^['"]?((?:@[^@/]+\/)?[^@(]+)@([^:'(]+)/);
      if (snapshotMatch && !packageMatch) {
        const [, name, version] = snapshotMatch;
        if (name && version && !packages.has(name)) {
          packages.set(name, {
            version: version.replace(/['"]/g, ''),
            isTransitive: true,
            dependencyChain: [],
          });
        }
      }
    }
  }
  
  return packages;
}

/**
 * Parse package-lock.json (npm)
 * @param {string} content - Raw JSON content
 * @returns {Map<string, Object>} Map of package name to { version, dependencyChain }
 */
function parseNpmLock(content) {
  const packages = new Map();
  
  try {
    const lockfile = JSON.parse(content);
    
    // Handle npm v7+ format (lockfileVersion 2 or 3)
    if (lockfile.packages) {
      for (const [pkgPath, pkgInfo] of Object.entries(lockfile.packages)) {
        // Skip root package
        if (pkgPath === '') continue;
        
        // Extract package name from path (e.g., "node_modules/@scope/pkg" -> "@scope/pkg")
        const match = pkgPath.match(/node_modules\/((?:@[^/]+\/)?[^/]+)$/);
        if (match) {
          const name = match[1];
          packages.set(name, {
            version: pkgInfo.version || 'unknown',
            isTransitive: !pkgInfo.dev && !pkgInfo.peer,
            dependencyChain: extractDependencyChain(pkgPath),
          });
        }
      }
    }
    
    // Handle npm v6 format (lockfileVersion 1)
    if (lockfile.dependencies) {
      parseNpmDependencies(lockfile.dependencies, packages, []);
    }
    
  } catch (error) {
    if (!options.json) {
      console.error(`${colors.yellow}⚠ Warning: Could not parse package-lock.json: ${error.message}${colors.reset}`);
    }
  }
  
  return packages;
}

/**
 * Recursively parse npm v6 dependencies format
 * @param {Object} deps - Dependencies object
 * @param {Map} packages - Map to populate
 * @param {Array} chain - Current dependency chain
 */
function parseNpmDependencies(deps, packages, chain) {
  for (const [name, info] of Object.entries(deps)) {
    packages.set(name, {
      version: info.version || 'unknown',
      isTransitive: chain.length > 0,
      dependencyChain: [...chain],
    });
    
    // Recurse into nested dependencies
    if (info.dependencies) {
      parseNpmDependencies(info.dependencies, packages, [...chain, name]);
    }
  }
}

/**
 * Extract dependency chain from npm package path
 * @param {string} pkgPath - Path like "node_modules/a/node_modules/b"
 * @returns {Array<string>} Dependency chain
 */
function extractDependencyChain(pkgPath) {
  const parts = pkgPath.split('/node_modules/').filter(p => p && p !== 'node_modules');
  return parts.slice(0, -1); // All except the last one (the package itself)
}

/**
 * Parse yarn.lock
 * @param {string} content - Raw yarn.lock content
 * @returns {Map<string, Object>} Map of package name to { version, dependencyChain }
 */
function parseYarnLock(content) {
  const packages = new Map();
  const lines = content.split('\n');
  
  let currentPackages = [];
  let currentVersion = null;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    
    // Skip empty lines and comments
    if (!trimmed || trimmed.startsWith('#')) continue;
    
    // Package declaration line (can have multiple packages on one line)
    // Format: "package@version", package@version: or "@scope/package@version":
    if (!line.startsWith(' ') && !line.startsWith('\t')) {
      // Parse package names from the line
      const pkgMatches = trimmed.matchAll(/["']?((?:@[^@,\s]+\/)?[^@,\s"']+)@[^,:\s"']+["']?/g);
      currentPackages = [];
      
      for (const match of pkgMatches) {
        if (match[1]) {
          currentPackages.push(match[1]);
        }
      }
      currentVersion = null;
    }
    
    // Version line
    if (line.startsWith('  version') && currentPackages.length > 0) {
      const versionMatch = trimmed.match(/version\s+["']?([^"'\s]+)["']?/);
      if (versionMatch) {
        currentVersion = versionMatch[1];
        
        for (const pkgName of currentPackages) {
          if (!packages.has(pkgName)) {
            packages.set(pkgName, {
              version: currentVersion,
              isTransitive: true,
              dependencyChain: [],
            });
          }
        }
      }
    }
  }
  
  return packages;
}

/**
 * Load and parse the project's lock file
 * @returns {Object|null} { type, packages: Map, filename } or null
 */
function loadLockFile() {
  const lockInfo = detectLockFile();
  
  if (!lockInfo) {
    return null;
  }
  
  try {
    const content = fs.readFileSync(lockInfo.path, 'utf8');
    let packages;
    
    switch (lockInfo.type) {
      case 'pnpm':
        packages = parsePnpmLock(content);
        break;
      case 'npm':
        packages = parseNpmLock(content);
        break;
      case 'yarn':
        packages = parseYarnLock(content);
        break;
      default:
        return null;
    }
    
    if (options.verbose && !options.json) {
      console.log(`${colors.dim}Lock file loaded: ${lockInfo.filename} (${packages.size} packages)${colors.reset}`);
    }
    
    return {
      type: lockInfo.type,
      packages,
      filename: lockInfo.filename,
    };
    
  } catch (error) {
    if (!options.json) {
      console.error(`${colors.yellow}⚠ Warning: Could not read ${lockInfo.filename}: ${error.message}${colors.reset}`);
    }
    return null;
  }
}

/**
 * Merge direct dependencies with transitive dependencies from lock file
 * @param {Object} directDeps - Direct dependencies from package.json
 * @param {Map} lockPackages - Packages from lock file
 * @returns {Object} Merged dependency info with chain tracking
 */
function mergeDependencies(directDeps, lockPackages) {
  const merged = new Map();
  const directNames = new Set(Object.keys(directDeps));
  
  // Add direct dependencies first
  for (const [name, version] of Object.entries(directDeps)) {
    merged.set(name, {
      version,
      isDirect: true,
      isTransitive: false,
      dependencyChain: [],
    });
  }
  
  // Add transitive dependencies from lock file
  for (const [name, info] of lockPackages) {
    if (!merged.has(name)) {
      merged.set(name, {
        version: info.version,
        isDirect: false,
        isTransitive: true,
        dependencyChain: info.dependencyChain || [],
      });
    } else {
      // Update version from lock file (more accurate)
      const existing = merged.get(name);
      existing.version = info.version;
    }
  }
  
  return merged;
}

/**
 * Check if a package matches a pattern (supports wildcards)
 * @param {string} packageName - Package to check
 * @param {string} pattern - Pattern to match (e.g., "@scope/*")
 * @returns {boolean} True if matches
 */
function matchesPattern(packageName, pattern) {
  if (pattern.endsWith('/*')) {
    const scope = pattern.slice(0, -2);
    return packageName.startsWith(scope + '/');
  }
  return packageName === pattern;
}

/**
 * Check if a package is in the trusted list
 * @param {string} packageName - Package to check
 * @param {Object} db - Threat database
 * @returns {boolean} True if trusted
 */
function isTrusted(packageName, db) {
  const trusted = db.trustedPackages?.packages || [];
  return trusted.some(pattern => matchesPattern(packageName, pattern));
}

/**
 * Check a package against the threat database
 * @param {string} packageName - Package name
 * @param {string} version - Package version
 * @param {Object} db - Threat database
 * @param {Object} depInfo - Optional dependency info { isDirect, isTransitive, dependencyChain }
 * @returns {Object|null} Issue object or null if clean
 */
function checkPackage(packageName, version, db, depInfo = null) {
  // Skip trusted packages
  if (isTrusted(packageName, db)) {
    return null;
  }
  
  // Check known malicious packages
  const malicious = db.knownMalicious || {};
  
  // Base issue properties (will be extended with specific type info)
  const baseIssue = {
    package: packageName,
    version,
    isDirect: depInfo?.isDirect ?? true,
    isTransitive: depInfo?.isTransitive ?? false,
    dependencyChain: depInfo?.dependencyChain || [],
  };
  
  // Check confirmed malicious
  if (malicious.confirmed?.includes(packageName)) {
    return {
      ...baseIssue,
      severity: 'critical',
      type: 'Confirmed Malicious',
      reason: 'This package has been confirmed as malicious',
      action: 'REMOVE IMMEDIATELY',
    };
  }
  
  // Check typosquatting
  if (malicious.typosquatting?.includes(packageName)) {
    return {
      ...baseIssue,
      severity: 'critical',
      type: 'Typosquatting',
      reason: 'This package name is a typosquatting variant of a popular package',
      action: 'REMOVE IMMEDIATELY - Check you have the correct package name',
    };
  }
  
  // Check credential theft
  if (malicious.credentialTheft?.includes(packageName)) {
    return {
      ...baseIssue,
      severity: 'critical',
      type: 'Credential Theft',
      reason: 'This package has been found to steal credentials',
      action: 'REMOVE IMMEDIATELY - Rotate all credentials',
    };
  }
  
  // Check crypto malware
  if (malicious.cryptoMalware?.includes(packageName)) {
    return {
      ...baseIssue,
      severity: 'critical',
      type: 'Crypto Malware',
      reason: 'This package contains cryptocurrency mining or wallet-stealing malware',
      action: 'REMOVE IMMEDIATELY - Check for unauthorized transactions',
    };
  }
  
  // Check campaigns
  const campaigns = db.campaigns || {};
  for (const [campaignId, campaign] of Object.entries(campaigns)) {
    if (campaign.packages?.includes(packageName)) {
      const affectedVersions = campaign.affectedVersions?.[packageName];
      const cleanVersion = version.replace(/^[\^~]/, '');
      
      // Check if specific version is affected
      if (affectedVersions && !affectedVersions.includes(cleanVersion)) {
        // Package is in campaign but this version might be safe
        return {
          ...baseIssue,
          severity: 'medium',
          type: campaign.name || campaignId,
          campaign: campaignId,
          reason: campaign.description || 'Part of known attack campaign',
          action: 'VERIFY VERSION - Some versions of this package are compromised',
          affectedVersions,
        };
      }
      
      return {
        ...baseIssue,
        severity: campaign.severity || 'high',
        type: campaign.name || campaignId,
        campaign: campaignId,
        reason: campaign.description || 'Part of known attack campaign',
        action: 'CHECK VERSION AND UPDATE',
        affectedVersions,
      };
    }
  }
  
  return null;
}

/**
 * Format a single issue for display
 * @param {Object} issue - Issue object
 * @returns {string} Formatted string
 */
function formatIssue(issue) {
  const severityColors = {
    critical: colors.red,
    high: colors.yellow,
    medium: colors.magenta,
    low: colors.cyan,
  };
  
  const severityIcons = {
    critical: '❌',
    high: '⚠',
    medium: '⚡',
    low: 'ℹ',
  };
  
  const color = severityColors[issue.severity] || colors.white;
  const icon = severityIcons[issue.severity] || '•';
  
  // Indicate if this is a transitive dependency
  const depTypeLabel = issue.isTransitive 
    ? `${colors.bgBlue}${colors.white} TRANSITIVE ${colors.reset} `
    : '';
  
  let output = `  ${icon} ${depTypeLabel}${color}${issue.package}@${issue.version}${colors.reset}\n`;
  output += `     ${colors.dim}Type:${colors.reset} ${issue.type}\n`;
  output += `     ${colors.dim}Reason:${colors.reset} ${issue.reason}\n`;
  output += `     ${colors.dim}Action:${colors.reset} ${colors.bold}${issue.action}${colors.reset}`;
  
  if (issue.affectedVersions) {
    output += `\n     ${colors.dim}Affected versions:${colors.reset} ${issue.affectedVersions.join(', ')}`;
  }
  
  // Show dependency chain for transitive dependencies
  if (issue.isTransitive && issue.dependencyChain && issue.dependencyChain.length > 0) {
    const chain = [...issue.dependencyChain, issue.package].join(' → ');
    output += `\n     ${colors.dim}Dependency chain:${colors.reset} ${colors.cyan}${chain}${colors.reset}`;
  } else if (issue.isTransitive) {
    output += `\n     ${colors.dim}Introduced via:${colors.reset} ${colors.cyan}transitive dependency${colors.reset}`;
  }
  
  return output;
}

/**
 * Print results in human-readable format
 * @param {Object} results - Scan results
 * @param {Object} scanStats - Scan statistics { total, direct, transitive, lockFileType }
 * @param {Object} db - Threat database
 */
function printResults(results, scanStats, db) {
  const separator = '━'.repeat(70);
  
  console.log(`\n${separator}`);
  console.log(`  ${colors.bold}🛡️  SECURITY SCAN RESULTS${colors.reset}`);
  console.log(separator);
  
  // Database info in verbose mode
  if (options.verbose) {
    console.log(`\n${colors.dim}Database version: ${db.version || 'unknown'}${colors.reset}`);
    console.log(`${colors.dim}Last updated: ${db.lastUpdated || 'unknown'}${colors.reset}`);
    
    // Count unique malicious packages (some appear in multiple categories)
    const allMalicious = new Set([
      ...(db.knownMalicious?.confirmed || []),
      ...(db.knownMalicious?.typosquatting || []),
      ...(db.knownMalicious?.credentialTheft || []),
      ...(db.knownMalicious?.cryptoMalware || []),
    ]);
    console.log(`${colors.dim}Known malicious packages: ${allMalicious.size}${colors.reset}\n`);
  }
  
  // Summary
  const totalIssues = Object.values(results).reduce((sum, arr) => sum + arr.length, 0);
  
  // Show scan mode and stats
  if (scanStats.lockFileType) {
    console.log(`\n${colors.bold}🔬 Scan mode:${colors.reset} ${colors.cyan}DEEP SCAN${colors.reset} (via ${scanStats.lockFileType})`);
    console.log(`${colors.bold}📦 Packages scanned:${colors.reset} ${scanStats.total}`);
    console.log(`   ${colors.dim}├─ Direct dependencies:${colors.reset} ${scanStats.direct}`);
    console.log(`   ${colors.dim}└─ Transitive dependencies:${colors.reset} ${scanStats.transitive}`);
  } else {
    console.log(`\n${colors.bold}🔍 Scan mode:${colors.reset} ${colors.dim}DIRECT ONLY${colors.reset} (use --deep for transitive)`);
    console.log(`${colors.bold}📦 Packages scanned:${colors.reset} ${scanStats.total}`);
  }
  
  console.log(`${colors.bold}🔍 Issues found:${colors.reset} ${totalIssues}`);
  
  // Count transitive issues
  if (scanStats.lockFileType && totalIssues > 0) {
    const transitiveIssues = Object.values(results)
      .flat()
      .filter(i => i.isTransitive).length;
    if (transitiveIssues > 0) {
      console.log(`   ${colors.yellow}└─ In transitive dependencies: ${transitiveIssues}${colors.reset}`);
    }
  }
  
  if (totalIssues === 0) {
    console.log(`\n${colors.green}✅ No security issues detected!${colors.reset}`);
    console.log(`${colors.dim}   All dependencies appear to be clean.${colors.reset}`);
    console.log(`\n${colors.green}✅ Security scan PASSED${colors.reset}\n`);
    return;
  }
  
  // Critical issues
  if (results.critical.length > 0) {
    console.log(`\n${colors.bgRed}${colors.white} 🚨 CRITICAL ISSUES (${results.critical.length}) ${colors.reset}`);
    console.log(separator);
    results.critical.forEach(issue => console.log(formatIssue(issue)));
  }
  
  // High severity
  if (results.high.length > 0) {
    console.log(`\n${colors.bgYellow}${colors.white} ⚠️  HIGH SEVERITY (${results.high.length}) ${colors.reset}`);
    console.log(separator);
    results.high.forEach(issue => console.log(formatIssue(issue)));
  }
  
  // Medium severity
  if (results.medium.length > 0) {
    console.log(`\n${colors.magenta}⚡ MEDIUM SEVERITY (${results.medium.length})${colors.reset}`);
    console.log(separator);
    results.medium.forEach(issue => console.log(formatIssue(issue)));
  }
  
  // Low severity
  if (results.low.length > 0) {
    console.log(`\n${colors.cyan}ℹ  LOW SEVERITY (${results.low.length})${colors.reset}`);
    console.log(separator);
    results.low.forEach(issue => console.log(formatIssue(issue)));
  }
  
  // Recommended actions
  if (results.critical.length > 0 || results.high.length > 0) {
    console.log(`\n${colors.bold}📋 RECOMMENDED ACTIONS:${colors.reset}`);
    console.log(separator);
    console.log(`  1. ${colors.red}IMMEDIATELY remove critical packages${colors.reset}`);
    console.log(`  2. Check for data exfiltration in logs`);
    console.log(`  3. Rotate all credentials and tokens`);
    console.log(`  4. Run full security audit: ${colors.cyan}pnpm audit${colors.reset}`);
    console.log(`  5. Check lock files for unauthorized changes`);
    console.log(`  6. Update all dependencies to latest secure versions`);
    console.log(`  7. Monitor security advisories regularly`);
    console.log(`\n${colors.red}❌ Security scan FAILED${colors.reset} - Critical/High severity issues found!\n`);
  } else {
    console.log(`\n${colors.yellow}⚠️  Security scan completed with warnings${colors.reset}\n`);
  }
}

/**
 * Print results in JSON format
 * @param {Object} results - Scan results
 * @param {Object} scanStats - Scan statistics
 */
function printJsonResults(results, scanStats) {
  const totalIssues = Object.values(results).reduce((sum, arr) => sum + arr.length, 0);
  const transitiveIssues = Object.values(results).flat().filter(i => i.isTransitive).length;
  
  const output = {
    timestamp: new Date().toISOString(),
    scanMode: scanStats.lockFileType ? 'deep' : 'direct',
    lockFile: scanStats.lockFileType || null,
    packagesScanned: {
      total: scanStats.total,
      direct: scanStats.direct,
      transitive: scanStats.transitive,
    },
    totalIssues,
    transitiveIssues,
    results: {
      critical: results.critical,
      high: results.high,
      medium: results.medium,
      low: results.low,
    },
  };
  
  console.log(JSON.stringify(output, null, 2));
}

/**
 * Main scan function
 */
async function scan() {
  if (!options.json) {
    console.log(`\n${colors.bold}🔍 Starting security scan...${colors.reset}\n`);
  }
  
  // Load database
  const db = loadCompromisedDb();
  if (!db) {
    process.exit(2);
  }
  
  // Load package.json
  const packageJson = loadPackageJson();
  if (!packageJson) {
    process.exit(2);
  }
  
  // Combine all direct dependencies
  const directDependencies = {
    ...packageJson.dependencies,
    ...packageJson.devDependencies,
    ...packageJson.peerDependencies,
    ...packageJson.optionalDependencies,
  };
  
  const directCount = Object.keys(directDependencies).length;
  
  if (directCount === 0) {
    if (!options.json) {
      console.log(`${colors.yellow}⚠ No dependencies found in package.json${colors.reset}\n`);
    }
    process.exit(0);
  }
  
  // Deep scan: load and parse lock file
  let allDependencies;
  let scanStats = {
    total: directCount,
    direct: directCount,
    transitive: 0,
    lockFileType: null,
  };
  
  if (options.deep) {
    if (!options.json) {
      console.log(`${colors.cyan}🔬 Deep scan enabled - analyzing lock file...${colors.reset}\n`);
    }
    
    const lockFile = loadLockFile();
    
    if (lockFile && lockFile.packages.size > 0) {
      allDependencies = mergeDependencies(directDependencies, lockFile.packages);
      scanStats.total = allDependencies.size;
      scanStats.transitive = allDependencies.size - directCount;
      scanStats.lockFileType = lockFile.filename;
      
      if (!options.json) {
        console.log(`${colors.green}✓ Found ${lockFile.packages.size} packages in ${lockFile.filename}${colors.reset}`);
        console.log(`${colors.dim}  (${directCount} direct + ${scanStats.transitive} transitive)${colors.reset}\n`);
      }
    } else {
      if (!options.json) {
        console.log(`${colors.yellow}⚠ No lock file found, falling back to direct dependencies only${colors.reset}`);
        console.log(`${colors.dim}  Run 'pnpm install' or 'npm install' to generate a lock file${colors.reset}\n`);
      }
      
      // Convert to Map format for consistency
      allDependencies = new Map();
      for (const [name, version] of Object.entries(directDependencies)) {
        allDependencies.set(name, {
          version,
          isDirect: true,
          isTransitive: false,
          dependencyChain: [],
        });
      }
    }
  } else {
    // Standard scan: direct dependencies only
    allDependencies = new Map();
    for (const [name, version] of Object.entries(directDependencies)) {
      allDependencies.set(name, {
        version,
        isDirect: true,
        isTransitive: false,
        dependencyChain: [],
      });
    }
  }
  
  if (options.verbose && !options.json) {
    console.log(`${colors.dim}Scanning ${allDependencies.size} packages...${colors.reset}\n`);
  }
  
  // Scan each package
  const results = {
    critical: [],
    high: [],
    medium: [],
    low: [],
  };
  
  for (const [packageName, depInfo] of allDependencies) {
    const version = depInfo.version;
    const issue = checkPackage(packageName, version, db, depInfo);
    
    if (options.verbose && !options.json) {
      const transitiveLabel = depInfo.isTransitive 
        ? `${colors.dim}[transitive]${colors.reset} ` 
        : '';
      
      if (issue) {
        const color = issue.severity === 'critical' ? colors.red : colors.yellow;
        console.log(`  ${color}✗${colors.reset} ${transitiveLabel}${color}${packageName}@${version}${colors.reset} - ${issue.type}`);
      } else if (isTrusted(packageName, db)) {
        console.log(`  ${colors.green}✓${colors.reset} ${transitiveLabel}${colors.dim}${packageName} - Trusted${colors.reset}`);
      } else {
        console.log(`  ${colors.green}✓${colors.reset} ${transitiveLabel}${packageName}`);
      }
    }
    
    if (issue) {
      results[issue.severity].push(issue);
    }
  }
  
  // Output results
  if (options.json) {
    printJsonResults(results, scanStats);
  } else {
    printResults(results, scanStats, db);
  }
  
  // Determine exit code
  const hasCritical = results.critical.length > 0;
  const hasHigh = results.high.length > 0;
  const hasMedium = results.medium.length > 0;
  const hasLow = results.low.length > 0;
  
  if (hasCritical || hasHigh) {
    process.exit(1);
  }
  
  if (options.strict && (hasMedium || hasLow)) {
    process.exit(1);
  }
  
  process.exit(0);
}

// Run the scanner
scan().catch(error => {
  console.error(`${colors.red}✗ Unexpected error: ${error.message}${colors.reset}`);
  process.exit(2);
});

