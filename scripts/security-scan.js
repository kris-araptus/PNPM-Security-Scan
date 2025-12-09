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
 *   --help, -h       Show help
 * 
 * Exit Codes:
 *   0 - No issues found
 *   1 - Critical/High severity issues found
 *   2 - Configuration or runtime error
 * 
 * @version 1.0.0
 * @author Kris Araptus
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
};

// Parse command line arguments
const args = process.argv.slice(2);
const options = {
  verbose: args.includes('--verbose') || args.includes('-v'),
  json: args.includes('--json'),
  strict: args.includes('--strict'),
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
  --help, -h       Show this help message

${colors.bold}Examples:${colors.reset}
  ${colors.cyan}pnpm run security:scan${colors.reset}              Quick scan
  ${colors.cyan}pnpm run security:scan:verbose${colors.reset}      Detailed scan
  ${colors.cyan}pnpm run security:scan -- --json${colors.reset}    JSON output

${colors.bold}Exit Codes:${colors.reset}
  ${colors.green}0${colors.reset} - All clear, no issues found
  ${colors.red}1${colors.reset} - Critical/High severity issues detected
  ${colors.yellow}2${colors.reset} - Configuration or runtime error

${colors.bold}Documentation:${colors.reset}
  ${colors.dim}docs/SECURITY-SCANNER.md${colors.reset}       Complete guide
  ${colors.dim}security/README.md${colors.reset}             Quick start
  ${colors.dim}README-SECURITY-SCANNER.md${colors.reset}     AI assistant prompt
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
 * @returns {Object|null} Issue object or null if clean
 */
function checkPackage(packageName, version, db) {
  // Skip trusted packages
  if (isTrusted(packageName, db)) {
    return null;
  }
  
  // Check known malicious packages
  const malicious = db.knownMalicious || {};
  
  // Check confirmed malicious
  if (malicious.confirmed?.includes(packageName)) {
    return {
      package: packageName,
      version,
      severity: 'critical',
      type: 'Confirmed Malicious',
      reason: 'This package has been confirmed as malicious',
      action: 'REMOVE IMMEDIATELY',
    };
  }
  
  // Check typosquatting
  if (malicious.typosquatting?.includes(packageName)) {
    return {
      package: packageName,
      version,
      severity: 'critical',
      type: 'Typosquatting',
      reason: 'This package name is a typosquatting variant of a popular package',
      action: 'REMOVE IMMEDIATELY - Check you have the correct package name',
    };
  }
  
  // Check credential theft
  if (malicious.credentialTheft?.includes(packageName)) {
    return {
      package: packageName,
      version,
      severity: 'critical',
      type: 'Credential Theft',
      reason: 'This package has been found to steal credentials',
      action: 'REMOVE IMMEDIATELY - Rotate all credentials',
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
          package: packageName,
          version,
          severity: 'medium',
          type: campaign.name || campaignId,
          campaign: campaignId,
          reason: campaign.description || 'Part of known attack campaign',
          action: 'VERIFY VERSION - Some versions of this package are compromised',
          affectedVersions,
        };
      }
      
      return {
        package: packageName,
        version,
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
  
  let output = `  ${icon} ${color}${issue.package}@${issue.version}${colors.reset}\n`;
  output += `     ${colors.dim}Type:${colors.reset} ${issue.type}\n`;
  output += `     ${colors.dim}Reason:${colors.reset} ${issue.reason}\n`;
  output += `     ${colors.dim}Action:${colors.reset} ${colors.bold}${issue.action}${colors.reset}`;
  
  if (issue.affectedVersions) {
    output += `\n     ${colors.dim}Affected versions:${colors.reset} ${issue.affectedVersions.join(', ')}`;
  }
  
  return output;
}

/**
 * Print results in human-readable format
 * @param {Object} results - Scan results
 * @param {number} totalScanned - Total packages scanned
 * @param {Object} db - Threat database
 */
function printResults(results, totalScanned, db) {
  const separator = '━'.repeat(70);
  
  console.log(`\n${separator}`);
  console.log(`  ${colors.bold}🛡️  SECURITY SCAN RESULTS${colors.reset}`);
  console.log(separator);
  
  // Database info in verbose mode
  if (options.verbose) {
    console.log(`\n${colors.dim}Database version: ${db.version || 'unknown'}${colors.reset}`);
    console.log(`${colors.dim}Last updated: ${db.lastUpdated || 'unknown'}${colors.reset}`);
    
    const maliciousCount = Object.values(db.knownMalicious || {})
      .reduce((sum, arr) => sum + (arr?.length || 0), 0);
    console.log(`${colors.dim}Known malicious packages: ${maliciousCount}${colors.reset}\n`);
  }
  
  // Summary
  const totalIssues = Object.values(results).reduce((sum, arr) => sum + arr.length, 0);
  console.log(`\n${colors.bold}📦 Packages scanned:${colors.reset} ${totalScanned}`);
  console.log(`${colors.bold}🔍 Issues found:${colors.reset} ${totalIssues}`);
  
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
 * @param {number} totalScanned - Total packages scanned
 */
function printJsonResults(results, totalScanned) {
  const totalIssues = Object.values(results).reduce((sum, arr) => sum + arr.length, 0);
  
  const output = {
    timestamp: new Date().toISOString(),
    packagesScanned: totalScanned,
    totalIssues,
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
  
  // Combine all dependencies
  const allDependencies = {
    ...packageJson.dependencies,
    ...packageJson.devDependencies,
    ...packageJson.peerDependencies,
    ...packageJson.optionalDependencies,
  };
  
  const packageNames = Object.keys(allDependencies);
  
  if (packageNames.length === 0) {
    if (!options.json) {
      console.log(`${colors.yellow}⚠ No dependencies found in package.json${colors.reset}\n`);
    }
    process.exit(0);
  }
  
  if (options.verbose && !options.json) {
    console.log(`${colors.dim}Scanning ${packageNames.length} dependencies...${colors.reset}\n`);
  }
  
  // Scan each package
  const results = {
    critical: [],
    high: [],
    medium: [],
    low: [],
  };
  
  for (const [packageName, version] of Object.entries(allDependencies)) {
    const issue = checkPackage(packageName, version, db);
    
    if (options.verbose && !options.json) {
      if (issue) {
        const color = issue.severity === 'critical' ? colors.red : colors.yellow;
        console.log(`  ${color}✗ ${packageName}@${version}${colors.reset} - ${issue.type}`);
      } else if (isTrusted(packageName, db)) {
        console.log(`  ${colors.green}✓${colors.reset} ${colors.dim}${packageName} - Trusted package${colors.reset}`);
      } else {
        console.log(`  ${colors.green}✓${colors.reset} ${packageName}`);
      }
    }
    
    if (issue) {
      results[issue.severity].push(issue);
    }
  }
  
  // Output results
  if (options.json) {
    printJsonResults(results, packageNames.length);
  } else {
    printResults(results, packageNames.length, db);
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

