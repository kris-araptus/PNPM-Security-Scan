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
const { execSync } = require('child_process');

// Package version
const SCANNER_VERSION = '2.0.0';

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
  deep: args.includes('--deep') || args.includes('-d'),
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
  --deep, -d             Deep scan: analyze lock files for transitive dependencies
  --analyze-scripts      Check postinstall scripts for suspicious patterns
  --strict               Fail on any risk level, not just critical/high

  ${colors.cyan}Output:${colors.reset}
  --json                 Output results in JSON format (for CI/CD)
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
  ${colors.cyan}pnpm run security:scan${colors.reset}                    Quick scan (direct deps only)
  ${colors.cyan}pnpm run security:scan -- --deep${colors.reset}          Deep scan (all transitive deps)
  ${colors.cyan}pnpm run security:scan -- --fix${colors.reset}           Remove bad packages
  ${colors.cyan}pnpm run security:scan -- --ignore pkg1,pkg2${colors.reset}
  ${colors.cyan}pnpm run security:scan -- --report${colors.reset}        Generate HTML report

${colors.bold}Lock File Support:${colors.reset}
  ${colors.dim}With --deep, scans transitive dependencies from:${colors.reset}
  • pnpm-lock.yaml  (pnpm)
  • package-lock.json (npm)
  • yarn.lock (yarn)

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
 * Get exact versions from lock files (for version matching in direct deps)
 * This is separate from loadLockFile() which does full deep scanning
 */
function getLockedVersions() {
  const projectRoot = findProjectRoot();
  const versions = {};
  
  // Try pnpm-lock.yaml first
  const pnpmLockPath = path.join(projectRoot, 'pnpm-lock.yaml');
  if (fs.existsSync(pnpmLockPath)) {
    if (options.verbose) {
      log(`${colors.dim}Reading versions from pnpm-lock.yaml${colors.reset}`);
    }
    try {
      const content = fs.readFileSync(pnpmLockPath, 'utf8');
      const packages = parsePnpmLock(content);
      for (const [name, info] of packages) {
        versions[name] = info.version;
      }
      return versions;
    } catch (error) {
      if (options.verbose) {
        log(`${colors.dim}Could not parse pnpm-lock.yaml: ${error.message}${colors.reset}`);
      }
    }
  }
  
  // Try package-lock.json
  const npmLockPath = path.join(projectRoot, 'package-lock.json');
  if (fs.existsSync(npmLockPath)) {
    if (options.verbose) {
      log(`${colors.dim}Reading versions from package-lock.json${colors.reset}`);
    }
    try {
      const content = fs.readFileSync(npmLockPath, 'utf8');
      const packages = parseNpmLock(content);
      for (const [name, info] of packages) {
        versions[name] = info.version;
      }
      return versions;
    } catch (error) {
      if (options.verbose) {
        log(`${colors.dim}Could not parse package-lock.json: ${error.message}${colors.reset}`);
      }
    }
  }
  
  // Try yarn.lock (basic support)
  const yarnLockPath = path.join(projectRoot, 'yarn.lock');
  if (fs.existsSync(yarnLockPath)) {
    if (options.verbose) {
      log(`${colors.dim}Reading versions from yarn.lock${colors.reset}`);
    }
    try {
      const content = fs.readFileSync(yarnLockPath, 'utf8');
      const packages = parseYarnLock(content);
      for (const [name, info] of packages) {
        versions[name] = info.version;
      }
      return versions;
    } catch (error) {
      if (options.verbose) {
        log(`${colors.dim}Could not parse yarn.lock: ${error.message}${colors.reset}`);
      }
    }
  }
  
  return versions;
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
 * @param {string} packageName - Package name
 * @param {string} version - Package version
 * @param {Object} db - Threat database
 * @param {Object} depInfo - Optional dependency info { isDirect, isTransitive, dependencyChain }
 * @param {Object} config - Configuration options
 * @returns {Object|null} Issue object or null if clean
 */
function checkPackage(packageName, version, db, depInfo = null, config = {}) {
  // Skip ignored packages
  if (isIgnored(packageName, config)) {
    return { ignored: true };
  }
  
  // Skip trusted packages
  if (isTrusted(packageName, db, config)) {
    return { trusted: true };
  }
  
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
  
  // Check protestware (with appropriate severity based on impact)
  const protestware = malicious.protestware || {};
  
  // High severity protestware (destructive - deletes/corrupts files)
  if (protestware.high?.packages?.includes(packageName)) {
    const details = protestware.high.details?.[packageName] || 'Destructive protestware';
    return {
      ...baseIssue,
      severity: 'high',
      type: 'Protestware (Destructive)',
      reason: details,
      action: 'REMOVE - Can delete or corrupt files on affected systems',
    };
  }
  
  // Medium severity protestware (DoS - infinite loops, crashes)
  if (protestware.medium?.packages?.includes(packageName)) {
    const details = protestware.medium.details?.[packageName] || 'DoS protestware';
    return {
      ...baseIssue,
      severity: 'medium',
      type: 'Protestware (DoS)',
      reason: details,
      action: 'REMOVE - Causes application hang or crash. Use alternative package.',
    };
  }
  
  // Low severity protestware (messages only, no functional impact)
  if (protestware.low?.packages?.includes(packageName)) {
    const details = protestware.low.details?.[packageName] || 'Protestware with political message';
    return {
      ...baseIssue,
      severity: 'low',
      type: 'Protestware (Message)',
      reason: details,
      action: 'OPTIONAL - No malicious behavior, contains political message only',
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
          ...baseIssue,
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
        ...baseIssue,
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
  
  // Indicate if this is a transitive dependency
  const depTypeLabel = issue.isTransitive 
    ? `${colors.bgBlue}${colors.white} TRANSITIVE ${colors.reset} `
    : '';
  
  let output = `  ${icon} ${depTypeLabel}${color}${issue.package}@${issue.version}${colors.reset}\n`;
  output += `     ${colors.dim}Type:${colors.reset} ${issue.type}\n`;
  output += `     ${colors.dim}Reason:${colors.reset} ${issue.reason}\n`;
  output += `     ${colors.dim}Action:${colors.reset} ${colors.bold}${issue.action}${colors.reset}`;
  
  if (issue.affectedVersions && !issue.safeVersion) {
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
  
  log(`\n${separator}`);
  log(`  ${colors.bold}🛡️  SECURITY SCAN RESULTS${colors.reset}`);
  log(separator);
  
  // Database info in verbose mode
  if (options.verbose) {
    log(`\n${colors.dim}Database version: ${db.version || 'unknown'}${colors.reset}`);
    log(`${colors.dim}Last updated: ${db.lastUpdated || 'unknown'}${colors.reset}`);
    
    // Count unique malicious packages (some appear in multiple categories)
    const allMalicious = new Set([
      ...(db.knownMalicious?.confirmed || []),
      ...(db.knownMalicious?.typosquatting || []),
      ...(db.knownMalicious?.credentialTheft || []),
      ...(db.knownMalicious?.cryptoMalware || []),
    ]);
    log(`${colors.dim}Known malicious packages: ${allMalicious.size}${colors.reset}`);
    log(`${colors.dim}Campaigns tracked: ${Object.keys(db.campaigns || {}).length}${colors.reset}\n`);
  }
  
  // Summary with colors
  const totalIssues = Object.values(results).reduce((sum, arr) => sum + arr.length, 0);
  
  // Show scan mode and stats
  if (scanStats.lockFileType) {
    log(`\n${colors.bold}🔬 Scan mode:${colors.reset} ${colors.cyan}DEEP SCAN${colors.reset} (via ${scanStats.lockFileType})`);
    log(`${colors.bold}📦 Packages scanned:${colors.reset} ${scanStats.total}`);
    log(`   ${colors.dim}├─ Direct dependencies:${colors.reset} ${scanStats.direct}`);
    log(`   ${colors.dim}└─ Transitive dependencies:${colors.reset} ${scanStats.transitive}`);
  } else {
    log(`\n${colors.bold}🔍 Scan mode:${colors.reset} ${colors.dim}DIRECT ONLY${colors.reset} (use --deep for transitive)`);
    log(`${colors.bold}📦 Packages scanned:${colors.reset} ${scanStats.total}`);
  }
  
  if (scanStats.ignored > 0) {
    log(`${colors.dim}📋 Packages ignored:${colors.reset} ${scanStats.ignored}`);
  }
  if (scanStats.trusted > 0) {
    log(`${colors.dim}✓  Trusted packages:${colors.reset} ${scanStats.trusted}`);
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
 * @param {Object} results - Scan results
 * @param {Object} scanStats - Scan statistics
 */
function printJsonResults(results, scanStats) {
  const totalIssues = Object.values(results).reduce((sum, arr) => sum + arr.length, 0);
  const transitiveIssues = Object.values(results).flat().filter(i => i.isTransitive).length;
  
  const output = {
    version: SCANNER_VERSION,
    timestamp: new Date().toISOString(),
    scanMode: scanStats.lockFileType ? 'deep' : 'direct',
    lockFile: scanStats.lockFileType || null,
    packagesScanned: {
      total: scanStats.total,
      direct: scanStats.direct,
      transitive: scanStats.transitive,
    },
    packagesIgnored: scanStats.ignored || 0,
    packagesTrusted: scanStats.trusted || 0,
    totalIssues,
    transitiveIssues,
    results: {
      critical: results.critical,
      high: results.high,
      medium: results.medium,
      low: results.low,
    },
    suspiciousScripts: scanStats.suspiciousScripts || [],
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
      log(`${colors.yellow}⚠ No dependencies found in package.json${colors.reset}\n`);
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
    ignored: 0,
    trusted: 0,
    suspiciousScripts: [],
  };
  
  if (mergedOptions.deep) {
    if (!options.json) {
      log(`${colors.cyan}🔬 Deep scan enabled - analyzing lock file...${colors.reset}\n`);
    }
    
    const lockFile = loadLockFile();
    
    if (lockFile && lockFile.packages.size > 0) {
      allDependencies = mergeDependencies(directDependencies, lockFile.packages);
      scanStats.total = allDependencies.size;
      scanStats.transitive = allDependencies.size - directCount;
      scanStats.lockFileType = lockFile.filename;
      
      if (!options.json) {
        log(`${colors.green}✓ Found ${lockFile.packages.size} packages in ${lockFile.filename}${colors.reset}`);
        log(`${colors.dim}  (${directCount} direct + ${scanStats.transitive} transitive)${colors.reset}\n`);
      }
    } else {
      if (!options.json) {
        log(`${colors.yellow}⚠ No lock file found, falling back to direct dependencies only${colors.reset}`);
        log(`${colors.dim}  Run 'pnpm install' or 'npm install' to generate a lock file${colors.reset}\n`);
      }
      
      // Convert to Map format for consistency
      allDependencies = new Map();
      for (const [name, version] of Object.entries(directDependencies)) {
        allDependencies.set(name, {
          version: lockedVersions[name] || version,
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
        version: lockedVersions[name] || version,
        isDirect: true,
        isTransitive: false,
        dependencyChain: [],
      });
    }
  }
  
  if (options.verbose && !options.json) {
    log(`${colors.dim}Scanning ${allDependencies.size} packages...${colors.reset}\n`);
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
    const result = checkPackage(packageName, version, db, depInfo, config);
    
    if (result?.ignored) {
      scanStats.ignored++;
      if (options.verbose && !options.json) {
        log(`  ${colors.dim}⊘ ${packageName} - Ignored${colors.reset}`);
      }
      continue;
    }
    
    if (result?.trusted) {
      scanStats.trusted++;
      if (options.verbose && !options.json) {
        const transitiveLabel = depInfo.isTransitive 
          ? `${colors.dim}[transitive]${colors.reset} ` 
          : '';
        log(`  ${colors.green}✓${colors.reset} ${transitiveLabel}${colors.dim}${packageName} - Trusted${colors.reset}`);
      }
      continue;
    }
    
    if (result) {
      const color = result.severity === 'critical' ? colors.red : colors.yellow;
      if (options.verbose && !options.json) {
        const transitiveLabel = depInfo.isTransitive 
          ? `${colors.dim}[transitive]${colors.reset} ` 
          : '';
        log(`  ${color}✗${colors.reset} ${transitiveLabel}${color}${packageName}@${version}${colors.reset} - ${result.type}`);
      }
      results[result.severity].push(result);
    } else if (options.verbose && !options.json) {
      const transitiveLabel = depInfo.isTransitive 
        ? `${colors.dim}[transitive]${colors.reset} ` 
        : '';
      log(`  ${colors.green}✓${colors.reset} ${transitiveLabel}${packageName}`);
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
            scanStats.suspiciousScripts.push({
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
    printJsonResults(results, scanStats);
  } else {
    printResults(results, scanStats, db);
  }
  
  // Generate HTML report if requested
  if (options.report) {
    generateHtmlReport(results, scanStats, db);
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
