#!/usr/bin/env node

/**
 * PNPM Security Scanner
 * 
 * Detects compromised npm packages in Node.js projects by scanning
 * dependencies against a configurable JSON threat database.
 * 
 * Built in response to the Shai-Hulud malware campaign (Sept 2025)
 * and other major supply chain attacks.
 * 
 * @version 1.2.0
 * @author Kris Araptus
 * @license MIT
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Package version
const SCANNER_VERSION = '1.2.0';

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

// Check if colors should be disabled
const NO_COLOR = process.env.NO_COLOR || process.env.TERM === 'dumb';
if (NO_COLOR) {
  Object.keys(colors).forEach(key => colors[key] = '');
}

// Parse command line arguments
const args = process.argv.slice(2);

/**
 * Get argument value (for --arg=value or --arg value)
 */
function getArgValue(argName) {
  const eqIndex = args.findIndex(a => a.startsWith(`--${argName}=`));
  if (eqIndex !== -1) {
    return args[eqIndex].split('=')[1];
  }
  const spaceIndex = args.indexOf(`--${argName}`);
  if (spaceIndex !== -1 && args[spaceIndex + 1] && !args[spaceIndex + 1].startsWith('-')) {
    return args[spaceIndex + 1];
  }
  return null;
}

const options = {
  verbose: args.includes('--verbose') || args.includes('-v'),
  json: args.includes('--json'),
  strict: args.includes('--strict'),
  help: args.includes('--help') || args.includes('-h'),
  version: args.includes('--version') || args.includes('-V'),
  silent: args.includes('--silent') || args.includes('-s'),
  fix: args.includes('--fix'),
  yes: args.includes('--yes') || args.includes('-y'),
  deep: args.includes('--deep'),
  analyzeScripts: args.includes('--analyze-scripts'),
  report: args.includes('--report'),
  update: args.includes('--update'),
  offline: args.includes('--offline'),
  ignore: getArgValue('ignore'),
  config: getArgValue('config'),
  reportPath: getArgValue('report-path'),
};

// Parsed ignore list
const ignoreList = options.ignore ? options.ignore.split(',').map(p => p.trim()) : [];

/**
 * Log function that respects silent mode
 */
function log(...args) {
  if (!options.silent && !options.json) {
    console.log(...args);
  }
}

/**
 * Display version
 */
function showVersion() {
  console.log(`pnpm-security-scanner v${SCANNER_VERSION}`);
  process.exit(0);
}

if (options.version) {
  showVersion();
}

/**
 * Display help information
 */
function showHelp() {
  console.log(`
${colors.bold}PNPM Security Scanner v${SCANNER_VERSION}${colors.reset}
${colors.dim}Detect compromised npm packages in your project${colors.reset}

${colors.bold}Usage:${colors.reset}
  node scripts/security-scan.js [options]
  pnpm run security:scan [-- options]

${colors.bold}Options:${colors.reset}
  ${colors.cyan}Scanning:${colors.reset}
  --verbose, -v          Show detailed output for each package
  --deep                 Scan transitive dependencies (node_modules)
  --analyze-scripts      Check postinstall scripts for suspicious patterns
  --strict               Fail on any risk level, not just critical/high

  ${colors.cyan}Output:${colors.reset}
  --json                 Output results in JSON format
  --silent, -s           Suppress all output except errors
  --report               Generate HTML report
  --report-path <path>   Path for HTML report (default: security-report.html)

  ${colors.cyan}Configuration:${colors.reset}
  --config <path>        Path to config file (default: .securityscanrc.json)
  --ignore <packages>    Comma-separated packages to ignore

  ${colors.cyan}Actions:${colors.reset}
  --fix                  Remove malicious packages (prompts for confirmation)
  --yes, -y              Auto-confirm --fix without prompting
  --update               Update threat database from remote source

  ${colors.cyan}Other:${colors.reset}
  --offline              Skip database age check
  --version, -V          Show version number
  --help, -h             Show this help message

${colors.bold}Examples:${colors.reset}
  ${colors.cyan}pnpm run security:scan${colors.reset}                    Quick scan
  ${colors.cyan}pnpm run security:scan -- --deep${colors.reset}          Scan all dependencies
  ${colors.cyan}pnpm run security:scan -- --fix${colors.reset}           Remove bad packages
  ${colors.cyan}pnpm run security:scan -- --ignore pkg1,pkg2${colors.reset}
  ${colors.cyan}pnpm run security:scan -- --report${colors.reset}        Generate HTML report

${colors.bold}Exit Codes:${colors.reset}
  ${colors.green}0${colors.reset} - All clear, no issues found
  ${colors.red}1${colors.reset} - Critical/High severity issues detected
  ${colors.yellow}2${colors.reset} - Configuration or runtime error

${colors.bold}Config File (.securityscanrc.json):${colors.reset}
  {
    "ignore": ["package-to-skip"],
    "failOn": ["critical", "high"],
    "scanDeep": false,
    "analyzeScripts": false
  }
`);
  process.exit(0);
}

if (options.help) {
  showHelp();
}

/**
 * Find the project root by looking for package.json
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
 * Load configuration file
 */
function loadConfig() {
  const projectRoot = findProjectRoot();
  const configPaths = [
    options.config,
    path.join(projectRoot, '.securityscanrc.json'),
    path.join(projectRoot, '.securityscanrc'),
    path.join(projectRoot, 'securityscan.config.json'),
  ].filter(Boolean);
  
  for (const configPath of configPaths) {
    if (fs.existsSync(configPath)) {
      try {
        const content = fs.readFileSync(configPath, 'utf8');
        const config = JSON.parse(content);
        if (options.verbose) {
          log(`${colors.dim}Config loaded from: ${configPath}${colors.reset}`);
        }
        return config;
      } catch (error) {
        log(`${colors.yellow}⚠ Error loading config: ${error.message}${colors.reset}`);
      }
    }
  }
  
  return {};
}

/**
 * Find the security database file
 */
function findSecurityDatabase() {
  const projectRoot = findProjectRoot();
  
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
 * Check database age and warn if old
 */
function checkDatabaseAge(db) {
  if (options.offline) return;
  
  const lastUpdated = db.lastUpdated;
  if (!lastUpdated) return;
  
  const updateDate = new Date(lastUpdated);
  const now = new Date();
  const daysDiff = Math.floor((now - updateDate) / (1000 * 60 * 60 * 24));
  
  if (daysDiff > 7) {
    log(`${colors.yellow}⚠ Database is ${daysDiff} days old. Run with --update to refresh.${colors.reset}`);
  }
}

/**
 * Load the compromised packages database
 */
function loadCompromisedDb() {
  const dbPath = findSecurityDatabase();
  
  if (!dbPath) {
    if (!options.silent) {
      console.error(`${colors.red}✗ Error: Could not find compromised-packages.json${colors.reset}`);
      console.error(`${colors.dim}  Looked in: security/, project root, and script directory${colors.reset}`);
    }
    return null;
  }
  
  try {
    const content = fs.readFileSync(dbPath, 'utf8');
    const db = JSON.parse(content);
    db._path = dbPath;
    
    if (options.verbose) {
      log(`${colors.dim}Database loaded from: ${dbPath}${colors.reset}`);
    }
    
    checkDatabaseAge(db);
    
    return db;
  } catch (error) {
    if (!options.silent) {
      console.error(`${colors.red}✗ Error loading database: ${error.message}${colors.reset}`);
    }
    return null;
  }
}

/**
 * Load the project's package.json
 */
function loadPackageJson() {
  const projectRoot = findProjectRoot();
  const packagePath = path.join(projectRoot, 'package.json');
  
  if (!fs.existsSync(packagePath)) {
    if (!options.silent) {
      console.error(`${colors.red}✗ Error: No package.json found in ${projectRoot}${colors.reset}`);
    }
    return null;
  }
  
  try {
    const content = fs.readFileSync(packagePath, 'utf8');
    return JSON.parse(content);
  } catch (error) {
    if (!options.silent) {
      console.error(`${colors.red}✗ Error reading package.json: ${error.message}${colors.reset}`);
    }
    return null;
  }
}

/**
 * Parse pnpm-lock.yaml to get exact versions
 */
function parsePnpmLock(lockPath) {
  const versions = {};
  
  try {
    const content = fs.readFileSync(lockPath, 'utf8');
    const lines = content.split('\n');
    
    // Simple YAML parsing for pnpm-lock.yaml
    let currentPackage = null;
    
    for (const line of lines) {
      // Match package entries like "  lodash@4.17.21:"
      const pkgMatch = line.match(/^\s{2}'?([^:@]+)@([^:]+)'?:/);
      if (pkgMatch) {
        const [, name, version] = pkgMatch;
        versions[name] = version.replace(/'/g, '');
      }
      
      // Match packages section entries
      const packagesMatch = line.match(/^\s{4}'?\/([^@]+)@([^(']+)/);
      if (packagesMatch) {
        const [, name, version] = packagesMatch;
        versions[name] = version.replace(/'/g, '').replace(/:$/, '');
      }
    }
  } catch (error) {
    if (options.verbose) {
      log(`${colors.dim}Could not parse pnpm-lock.yaml: ${error.message}${colors.reset}`);
    }
  }
  
  return versions;
}

/**
 * Parse package-lock.json to get exact versions
 */
function parseNpmLock(lockPath) {
  const versions = {};
  
  try {
    const content = fs.readFileSync(lockPath, 'utf8');
    const lock = JSON.parse(content);
    
    // npm lockfile v2/v3
    if (lock.packages) {
      for (const [pkgPath, pkg] of Object.entries(lock.packages)) {
        if (pkgPath === '') continue; // Skip root
        const name = pkgPath.replace('node_modules/', '').replace(/^.*node_modules\//, '');
        if (pkg.version) {
          versions[name] = pkg.version;
        }
      }
    }
    
    // npm lockfile v1
    if (lock.dependencies) {
      function extractDeps(deps, prefix = '') {
        for (const [name, dep] of Object.entries(deps)) {
          if (dep.version) {
            versions[name] = dep.version;
          }
          if (dep.dependencies) {
            extractDeps(dep.dependencies);
          }
        }
      }
      extractDeps(lock.dependencies);
    }
  } catch (error) {
    if (options.verbose) {
      log(`${colors.dim}Could not parse package-lock.json: ${error.message}${colors.reset}`);
    }
  }
  
  return versions;
}

/**
 * Get exact versions from lock files
 */
function getLockedVersions() {
  const projectRoot = findProjectRoot();
  
  // Try pnpm-lock.yaml first
  const pnpmLock = path.join(projectRoot, 'pnpm-lock.yaml');
  if (fs.existsSync(pnpmLock)) {
    if (options.verbose) {
      log(`${colors.dim}Reading versions from pnpm-lock.yaml${colors.reset}`);
    }
    return parsePnpmLock(pnpmLock);
  }
  
  // Try package-lock.json
  const npmLock = path.join(projectRoot, 'package-lock.json');
  if (fs.existsSync(npmLock)) {
    if (options.verbose) {
      log(`${colors.dim}Reading versions from package-lock.json${colors.reset}`);
    }
    return parseNpmLock(npmLock);
  }
  
  // Try yarn.lock (basic support)
  const yarnLock = path.join(projectRoot, 'yarn.lock');
  if (fs.existsSync(yarnLock)) {
    if (options.verbose) {
      log(`${colors.dim}yarn.lock found but not fully supported, using package.json versions${colors.reset}`);
    }
  }
  
  return {};
}

/**
 * Scan node_modules for transitive dependencies
 */
function scanNodeModules() {
  const projectRoot = findProjectRoot();
  const nodeModules = path.join(projectRoot, 'node_modules');
  const packages = {};
  
  if (!fs.existsSync(nodeModules)) {
    return packages;
  }
  
  function scanDir(dir, prefix = '') {
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      
      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        
        const name = entry.name;
        const fullPath = path.join(dir, name);
        
        // Handle scoped packages
        if (name.startsWith('@')) {
          scanDir(fullPath, name + '/');
          continue;
        }
        
        const pkgJsonPath = path.join(fullPath, 'package.json');
        if (fs.existsSync(pkgJsonPath)) {
          try {
            const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
            const fullName = prefix + name;
            packages[fullName] = {
              version: pkg.version,
              scripts: pkg.scripts || {},
              path: fullPath,
            };
          } catch (e) {
            // Skip invalid package.json
          }
        }
      }
    } catch (error) {
      // Permission or other errors
    }
  }
  
  scanDir(nodeModules);
  return packages;
}

/**
 * Analyze postinstall scripts for suspicious patterns
 */
function analyzeScript(script, patterns) {
  const matches = [];
  
  if (!script) return matches;
  
  const scriptLower = script.toLowerCase();
  
  for (const pattern of patterns) {
    if (scriptLower.includes(pattern.toLowerCase())) {
      matches.push(pattern);
    }
  }
  
  return matches;
}

/**
 * Check if a package matches a pattern (supports wildcards)
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
 */
function isTrusted(packageName, db, config) {
  const trusted = [
    ...(db.trustedPackages?.packages || []),
    ...(config.trustedPackages || []),
  ];
  return trusted.some(pattern => matchesPattern(packageName, pattern));
}

/**
 * Check if a package should be ignored
 */
function isIgnored(packageName, config) {
  const ignored = [
    ...ignoreList,
    ...(config.ignore || []),
  ];
  return ignored.some(pattern => matchesPattern(packageName, pattern));
}

/**
 * Check if a version matches affected versions
 */
function isVersionAffected(version, affectedVersions) {
  if (!affectedVersions || affectedVersions.length === 0) {
    return true; // No specific versions = all affected
  }
  
  // Clean version (remove ^, ~, etc)
  const cleanVersion = version.replace(/^[\^~>=<]*/g, '').split(' ')[0];
  
  return affectedVersions.includes(cleanVersion);
}

/**
 * Check a package against the threat database
 */
function checkPackage(packageName, version, db, config) {
  // Skip ignored packages
  if (isIgnored(packageName, config)) {
    return { ignored: true };
  }
  
  // Skip trusted packages
  if (isTrusted(packageName, db, config)) {
    return { trusted: true };
  }
  
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
  
  // Check crypto malware
  if (malicious.cryptoMalware?.includes(packageName)) {
    return {
      package: packageName,
      version,
      severity: 'critical',
      type: 'Crypto Malware',
      reason: 'This package contains cryptocurrency-related malware',
      action: 'REMOVE IMMEDIATELY - Check for unauthorized transactions',
    };
  }
  
  // Check campaigns with version matching
  const campaigns = db.campaigns || {};
  for (const [campaignId, campaign] of Object.entries(campaigns)) {
    // Check if package is in campaign's packages list
    if (campaign.packages?.includes(packageName)) {
      const affectedVersions = campaign.affectedVersions?.[packageName];
      
      if (affectedVersions && !isVersionAffected(version, affectedVersions)) {
        return {
          package: packageName,
          version,
          severity: 'low',
          type: campaign.name || campaignId,
          campaign: campaignId,
          reason: 'Package was part of attack campaign but your version appears safe',
          action: 'VERIFY - Ensure you are on a safe version',
          affectedVersions,
          safeVersion: true,
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
    
    // Check affectedVersions for version-specific compromises
    const affectedVersions = campaign.affectedVersions?.[packageName];
    if (affectedVersions) {
      if (isVersionAffected(version, affectedVersions)) {
        return {
          package: packageName,
          version,
          severity: 'critical',
          type: campaign.name || campaignId,
          campaign: campaignId,
          reason: `This specific version was compromised in the ${campaign.name || campaignId} attack`,
          action: 'UPDATE TO SAFE VERSION IMMEDIATELY',
          affectedVersions,
        };
      }
    }
  }
  
  return null;
}

/**
 * Format a single issue for display
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
    high: '⚠️',
    medium: '⚡',
    low: 'ℹ️',
  };
  
  const color = severityColors[issue.severity] || colors.white;
  const icon = severityIcons[issue.severity] || '•';
  
  let output = `  ${icon} ${color}${issue.package}@${issue.version}${colors.reset}\n`;
  output += `     ${colors.dim}Type:${colors.reset} ${issue.type}\n`;
  output += `     ${colors.dim}Reason:${colors.reset} ${issue.reason}\n`;
  output += `     ${colors.dim}Action:${colors.reset} ${colors.bold}${issue.action}${colors.reset}`;
  
  if (issue.affectedVersions && !issue.safeVersion) {
    output += `\n     ${colors.dim}Affected versions:${colors.reset} ${issue.affectedVersions.join(', ')}`;
  }
  
  return output;
}

/**
 * Print results in human-readable format
 */
function printResults(results, stats, db) {
  const separator = '━'.repeat(70);
  
  log(`\n${separator}`);
  log(`  ${colors.bold}🛡️  SECURITY SCAN RESULTS${colors.reset}`);
  log(separator);
  
  // Database info in verbose mode
  if (options.verbose) {
    log(`\n${colors.dim}Database version: ${db.version || 'unknown'}${colors.reset}`);
    log(`${colors.dim}Last updated: ${db.lastUpdated || 'unknown'}${colors.reset}`);
    
    const maliciousCount = Object.values(db.knownMalicious || {})
      .reduce((sum, arr) => sum + (arr?.length || 0), 0);
    log(`${colors.dim}Known malicious packages: ${maliciousCount}${colors.reset}`);
    log(`${colors.dim}Campaigns tracked: ${Object.keys(db.campaigns || {}).length}${colors.reset}\n`);
  }
  
  // Summary with colors
  const totalIssues = Object.values(results).reduce((sum, arr) => sum + arr.length, 0);
  log(`\n${colors.bold}📦 Packages scanned:${colors.reset} ${stats.total}`);
  
  if (stats.ignored > 0) {
    log(`${colors.dim}📋 Packages ignored:${colors.reset} ${stats.ignored}`);
  }
  if (stats.trusted > 0) {
    log(`${colors.dim}✓  Trusted packages:${colors.reset} ${stats.trusted}`);
  }
  
  // Issue counts with colors
  log(`\n${colors.bold}🔍 Issues found:${colors.reset} ${totalIssues}`);
  if (results.critical.length > 0) {
    log(`   ${colors.red}Critical: ${results.critical.length}${colors.reset}`);
  }
  if (results.high.length > 0) {
    log(`   ${colors.yellow}High: ${results.high.length}${colors.reset}`);
  }
  if (results.medium.length > 0) {
    log(`   ${colors.magenta}Medium: ${results.medium.length}${colors.reset}`);
  }
  if (results.low.length > 0) {
    log(`   ${colors.cyan}Low: ${results.low.length}${colors.reset}`);
  }
  
  if (totalIssues === 0) {
    log(`\n${colors.green}✅ No security issues detected!${colors.reset}`);
    log(`${colors.dim}   All dependencies appear to be clean.${colors.reset}`);
    log(`\n${colors.green}✅ Security scan PASSED${colors.reset}\n`);
    return;
  }
  
  // Critical issues
  if (results.critical.length > 0) {
    log(`\n${colors.bgRed}${colors.white} 🚨 CRITICAL ISSUES (${results.critical.length}) ${colors.reset}`);
    log(separator);
    results.critical.forEach(issue => log(formatIssue(issue)));
  }
  
  // High severity
  if (results.high.length > 0) {
    log(`\n${colors.bgYellow}${colors.white} ⚠️  HIGH SEVERITY (${results.high.length}) ${colors.reset}`);
    log(separator);
    results.high.forEach(issue => log(formatIssue(issue)));
  }
  
  // Medium severity
  if (results.medium.length > 0) {
    log(`\n${colors.magenta}⚡ MEDIUM SEVERITY (${results.medium.length})${colors.reset}`);
    log(separator);
    results.medium.forEach(issue => log(formatIssue(issue)));
  }
  
  // Low severity
  if (results.low.length > 0) {
    log(`\n${colors.cyan}ℹ  LOW SEVERITY (${results.low.length})${colors.reset}`);
    log(separator);
    results.low.forEach(issue => log(formatIssue(issue)));
  }
  
  // Script analysis results
  if (stats.suspiciousScripts && stats.suspiciousScripts.length > 0) {
    log(`\n${colors.yellow}⚠️  SUSPICIOUS SCRIPTS (${stats.suspiciousScripts.length})${colors.reset}`);
    log(separator);
    for (const item of stats.suspiciousScripts) {
      log(`  ⚠️  ${colors.yellow}${item.package}${colors.reset}`);
      log(`     ${colors.dim}Script:${colors.reset} ${item.scriptType}`);
      log(`     ${colors.dim}Patterns found:${colors.reset} ${item.patterns.join(', ')}`);
    }
  }
  
  // Recommended actions
  if (results.critical.length > 0 || results.high.length > 0) {
    log(`\n${colors.bold}📋 RECOMMENDED ACTIONS:${colors.reset}`);
    log(separator);
    log(`  1. ${colors.red}IMMEDIATELY remove critical packages${colors.reset}`);
    log(`  2. Check for data exfiltration in logs`);
    log(`  3. Rotate all credentials and tokens`);
    log(`  4. Run full security audit: ${colors.cyan}pnpm audit${colors.reset}`);
    log(`  5. Check lock files for unauthorized changes`);
    
    if (options.fix) {
      log(`\n${colors.cyan}💡 Run with --fix to automatically remove malicious packages${colors.reset}`);
    }
    
    log(`\n${colors.red}❌ Security scan FAILED${colors.reset} - Critical/High severity issues found!\n`);
  } else {
    log(`\n${colors.yellow}⚠️  Security scan completed with warnings${colors.reset}\n`);
  }
}

/**
 * Print results in JSON format
 */
function printJsonResults(results, stats) {
  const totalIssues = Object.values(results).reduce((sum, arr) => sum + arr.length, 0);
  
  const output = {
    version: SCANNER_VERSION,
    timestamp: new Date().toISOString(),
    packagesScanned: stats.total,
    packagesIgnored: stats.ignored,
    packagesTrusted: stats.trusted,
    totalIssues,
    results: {
      critical: results.critical,
      high: results.high,
      medium: results.medium,
      low: results.low,
    },
    suspiciousScripts: stats.suspiciousScripts || [],
  };
  
  console.log(JSON.stringify(output, null, 2));
}

/**
 * Generate HTML report
 */
function generateHtmlReport(results, stats, db) {
  const totalIssues = Object.values(results).reduce((sum, arr) => sum + arr.length, 0);
  const projectRoot = findProjectRoot();
  const reportPath = options.reportPath || path.join(projectRoot, 'security-report.html');
  
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Scan Report</title>
  <style>
    :root {
      --critical: #dc2626;
      --high: #f59e0b;
      --medium: #8b5cf6;
      --low: #06b6d4;
      --success: #10b981;
      --bg: #0f172a;
      --card: #1e293b;
      --text: #e2e8f0;
      --dim: #64748b;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 2rem;
    }
    .container { max-width: 1000px; margin: 0 auto; }
    h1 { font-size: 2rem; margin-bottom: 0.5rem; }
    .subtitle { color: var(--dim); margin-bottom: 2rem; }
    .summary { 
      display: grid; 
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); 
      gap: 1rem; 
      margin-bottom: 2rem;
    }
    .stat { 
      background: var(--card); 
      padding: 1.5rem; 
      border-radius: 0.5rem; 
      text-align: center;
    }
    .stat-value { font-size: 2rem; font-weight: bold; }
    .stat-label { color: var(--dim); font-size: 0.875rem; }
    .stat-critical .stat-value { color: var(--critical); }
    .stat-high .stat-value { color: var(--high); }
    .stat-medium .stat-value { color: var(--medium); }
    .stat-low .stat-value { color: var(--low); }
    .stat-success .stat-value { color: var(--success); }
    .section { margin-bottom: 2rem; }
    .section-title { 
      font-size: 1.25rem; 
      padding: 0.75rem 1rem; 
      border-radius: 0.5rem 0.5rem 0 0;
      margin-bottom: 0;
    }
    .section-critical .section-title { background: var(--critical); }
    .section-high .section-title { background: var(--high); color: #000; }
    .section-medium .section-title { background: var(--medium); }
    .section-low .section-title { background: var(--low); }
    .issues { background: var(--card); border-radius: 0 0 0.5rem 0.5rem; }
    .issue { padding: 1rem; border-bottom: 1px solid var(--bg); }
    .issue:last-child { border-bottom: none; }
    .issue-name { font-weight: bold; font-size: 1.1rem; }
    .issue-meta { color: var(--dim); font-size: 0.875rem; margin-top: 0.5rem; }
    .issue-action { 
      margin-top: 0.5rem; 
      padding: 0.5rem; 
      background: rgba(255,255,255,0.05); 
      border-radius: 0.25rem;
      font-family: monospace;
    }
    .footer { text-align: center; color: var(--dim); margin-top: 2rem; font-size: 0.875rem; }
    .success-banner {
      background: var(--success);
      color: #000;
      padding: 2rem;
      border-radius: 0.5rem;
      text-align: center;
      font-size: 1.5rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ Security Scan Report</h1>
    <p class="subtitle">Generated: ${new Date().toLocaleString()} | Database: v${db.version}</p>
    
    <div class="summary">
      <div class="stat">
        <div class="stat-value">${stats.total}</div>
        <div class="stat-label">Packages Scanned</div>
      </div>
      <div class="stat stat-critical">
        <div class="stat-value">${results.critical.length}</div>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat stat-high">
        <div class="stat-value">${results.high.length}</div>
        <div class="stat-label">High</div>
      </div>
      <div class="stat stat-medium">
        <div class="stat-value">${results.medium.length}</div>
        <div class="stat-label">Medium</div>
      </div>
      <div class="stat stat-low">
        <div class="stat-value">${results.low.length}</div>
        <div class="stat-label">Low</div>
      </div>
    </div>
    
    ${totalIssues === 0 ? `
    <div class="success-banner">
      ✅ No security issues detected!
    </div>
    ` : ''}
    
    ${results.critical.length > 0 ? `
    <div class="section section-critical">
      <h2 class="section-title">🚨 Critical Issues (${results.critical.length})</h2>
      <div class="issues">
        ${results.critical.map(i => `
        <div class="issue">
          <div class="issue-name">${i.package}@${i.version}</div>
          <div class="issue-meta"><strong>Type:</strong> ${i.type}</div>
          <div class="issue-meta"><strong>Reason:</strong> ${i.reason}</div>
          <div class="issue-action">⚡ ${i.action}</div>
        </div>
        `).join('')}
      </div>
    </div>
    ` : ''}
    
    ${results.high.length > 0 ? `
    <div class="section section-high">
      <h2 class="section-title">⚠️ High Severity (${results.high.length})</h2>
      <div class="issues">
        ${results.high.map(i => `
        <div class="issue">
          <div class="issue-name">${i.package}@${i.version}</div>
          <div class="issue-meta"><strong>Type:</strong> ${i.type}</div>
          <div class="issue-meta"><strong>Reason:</strong> ${i.reason}</div>
          <div class="issue-action">⚡ ${i.action}</div>
        </div>
        `).join('')}
      </div>
    </div>
    ` : ''}
    
    ${results.medium.length > 0 ? `
    <div class="section section-medium">
      <h2 class="section-title">⚡ Medium Severity (${results.medium.length})</h2>
      <div class="issues">
        ${results.medium.map(i => `
        <div class="issue">
          <div class="issue-name">${i.package}@${i.version}</div>
          <div class="issue-meta"><strong>Type:</strong> ${i.type}</div>
          <div class="issue-action">⚡ ${i.action}</div>
        </div>
        `).join('')}
      </div>
    </div>
    ` : ''}
    
    ${results.low.length > 0 ? `
    <div class="section section-low">
      <h2 class="section-title">ℹ️ Low Severity (${results.low.length})</h2>
      <div class="issues">
        ${results.low.map(i => `
        <div class="issue">
          <div class="issue-name">${i.package}@${i.version}</div>
          <div class="issue-meta"><strong>Type:</strong> ${i.type}</div>
        </div>
        `).join('')}
      </div>
    </div>
    ` : ''}
    
    <div class="footer">
      PNPM Security Scanner v${SCANNER_VERSION} | Database updated: ${db.lastUpdated}
    </div>
  </div>
</body>
</html>`;

  fs.writeFileSync(reportPath, html);
  log(`\n${colors.green}📄 HTML report generated: ${reportPath}${colors.reset}`);
}

/**
 * Remove malicious packages
 */
function fixPackages(issues) {
  if (issues.length === 0) {
    log(`${colors.green}✓ No packages to remove${colors.reset}`);
    return;
  }
  
  const packageNames = issues.map(i => i.package);
  
  log(`\n${colors.yellow}The following packages will be removed:${colors.reset}`);
  packageNames.forEach(p => log(`  - ${colors.red}${p}${colors.reset}`));
  
  if (!options.yes) {
    log(`\n${colors.yellow}Run with --yes to confirm removal${colors.reset}`);
    return;
  }
  
  // Detect package manager
  const projectRoot = findProjectRoot();
  let pm = 'npm';
  if (fs.existsSync(path.join(projectRoot, 'pnpm-lock.yaml'))) {
    pm = 'pnpm';
  } else if (fs.existsSync(path.join(projectRoot, 'yarn.lock'))) {
    pm = 'yarn';
  }
  
  log(`\n${colors.cyan}Removing packages using ${pm}...${colors.reset}`);
  
  try {
    const cmd = pm === 'yarn' 
      ? `yarn remove ${packageNames.join(' ')}`
      : `${pm} remove ${packageNames.join(' ')}`;
    
    execSync(cmd, { cwd: projectRoot, stdio: 'inherit' });
    log(`\n${colors.green}✓ Packages removed successfully${colors.reset}`);
  } catch (error) {
    log(`${colors.red}✗ Error removing packages: ${error.message}${colors.reset}`);
  }
}

/**
 * Main scan function
 */
async function scan() {
  log(`\n${colors.bold}🔍 Starting security scan...${colors.reset}\n`);
  
  // Load config
  const config = loadConfig();
  
  // Merge config with CLI options
  const mergedOptions = {
    ...config,
    verbose: options.verbose || config.verbose,
    strict: options.strict || config.strict,
    deep: options.deep || config.scanDeep,
    analyzeScripts: options.analyzeScripts || config.analyzeScripts,
  };
  
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
  
  // Get locked versions for accurate matching
  const lockedVersions = getLockedVersions();
  
  // Combine all dependencies
  let allDependencies = {
    ...packageJson.dependencies,
    ...packageJson.devDependencies,
    ...packageJson.peerDependencies,
    ...packageJson.optionalDependencies,
  };
  
  // Add transitive dependencies if --deep
  if (mergedOptions.deep) {
    log(`${colors.dim}Scanning transitive dependencies...${colors.reset}`);
    const nodeModulesPackages = scanNodeModules();
    for (const [name, pkg] of Object.entries(nodeModulesPackages)) {
      if (!allDependencies[name]) {
        allDependencies[name] = pkg.version;
      }
    }
  }
  
  const packageNames = Object.keys(allDependencies);
  
  if (packageNames.length === 0) {
    log(`${colors.yellow}⚠ No dependencies found in package.json${colors.reset}\n`);
    process.exit(0);
  }
  
  if (options.verbose) {
    log(`${colors.dim}Scanning ${packageNames.length} dependencies...${colors.reset}\n`);
  }
  
  // Stats
  const stats = {
    total: packageNames.length,
    ignored: 0,
    trusted: 0,
    suspiciousScripts: [],
  };
  
  // Scan each package
  const results = {
    critical: [],
    high: [],
    medium: [],
    low: [],
  };
  
  for (const [packageName, declaredVersion] of Object.entries(allDependencies)) {
    // Use locked version if available
    const version = lockedVersions[packageName] || declaredVersion;
    
    const result = checkPackage(packageName, version, db, config);
    
    if (result?.ignored) {
      stats.ignored++;
      if (options.verbose) {
        log(`  ${colors.dim}⊘ ${packageName} - Ignored${colors.reset}`);
      }
      continue;
    }
    
    if (result?.trusted) {
      stats.trusted++;
      if (options.verbose) {
        log(`  ${colors.green}✓${colors.reset} ${colors.dim}${packageName} - Trusted${colors.reset}`);
      }
      continue;
    }
    
    if (result) {
      const color = result.severity === 'critical' ? colors.red : colors.yellow;
      if (options.verbose) {
        log(`  ${color}✗ ${packageName}@${version}${colors.reset} - ${result.type}`);
      }
      results[result.severity].push(result);
    } else if (options.verbose) {
      log(`  ${colors.green}✓${colors.reset} ${packageName}`);
    }
  }
  
  // Analyze postinstall scripts if requested
  if (mergedOptions.analyzeScripts) {
    log(`\n${colors.dim}Analyzing postinstall scripts...${colors.reset}`);
    const nodeModulesPackages = scanNodeModules();
    const patterns = db.indicators?.postinstall?.patterns || [];
    
    for (const [name, pkg] of Object.entries(nodeModulesPackages)) {
      for (const scriptType of ['preinstall', 'install', 'postinstall']) {
        const script = pkg.scripts?.[scriptType];
        if (script) {
          const matches = analyzeScript(script, patterns);
          if (matches.length > 0) {
            stats.suspiciousScripts.push({
              package: name,
              scriptType,
              patterns: matches,
            });
          }
        }
      }
    }
  }
  
  // Output results
  if (options.json) {
    printJsonResults(results, stats);
  } else {
    printResults(results, stats, db);
  }
  
  // Generate HTML report if requested
  if (options.report) {
    generateHtmlReport(results, stats, db);
  }
  
  // Fix packages if requested
  if (options.fix) {
    const criticalAndHigh = [...results.critical, ...results.high];
    fixPackages(criticalAndHigh);
  }
  
  // Determine exit code
  const hasCritical = results.critical.length > 0;
  const hasHigh = results.high.length > 0;
  const hasMedium = results.medium.length > 0;
  const hasLow = results.low.length > 0;
  
  // Check against configured fail levels
  const failOn = config.failOn || ['critical', 'high'];
  
  if (failOn.includes('critical') && hasCritical) {
    process.exit(1);
  }
  if (failOn.includes('high') && hasHigh) {
    process.exit(1);
  }
  if ((failOn.includes('medium') || options.strict) && hasMedium) {
    process.exit(1);
  }
  if ((failOn.includes('low') || options.strict) && hasLow) {
    process.exit(1);
  }
  
  process.exit(0);
}

// Run the scanner
scan().catch(error => {
  if (!options.silent) {
    console.error(`${colors.red}✗ Unexpected error: ${error.message}${colors.reset}`);
  }
  process.exit(2);
});
