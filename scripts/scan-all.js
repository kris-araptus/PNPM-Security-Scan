#!/usr/bin/env node

/**
 * Multi-Project Security Scanner
 * 
 * Scans multiple Node.js projects in a directory for compromised packages.
 * 
 * Usage:
 *   node scripts/scan-all.js <directory>
 *   node scripts/scan-all.js ~/projects
 *   node scripts/scan-all.js . --depth 2
 * 
 * @version 1.0.0
 * @author Kris Araptus
 * @license MIT
 */

const fs = require('fs');
const path = require('path');
const { execSync, spawn } = require('child_process');

// ANSI colors
const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
};

// Parse arguments
const args = process.argv.slice(2);
const targetDir = args.find(a => !a.startsWith('-')) || '.';
const maxDepth = args.includes('--depth') 
  ? parseInt(args[args.indexOf('--depth') + 1]) || 2 
  : 2;
const jsonOutput = args.includes('--json');
const verbose = args.includes('--verbose') || args.includes('-v');
const showHelp = args.includes('--help') || args.includes('-h');
const parallel = args.includes('--parallel');
const fromList = args.includes('--from-list');
const listPath = args.includes('--list') 
  ? args[args.indexOf('--list') + 1] 
  : null;
const addProject = args.includes('--add') 
  ? args[args.indexOf('--add') + 1] 
  : null;
const addAll = args.includes('--add-all') 
  ? args[args.indexOf('--add-all') + 1] 
  : null;
const removeProject = args.includes('--remove')
  ? args[args.indexOf('--remove') + 1]
  : null;
const showList = args.includes('--show-list');

// Projects list locations (checked in order)
const localListPath = path.join(process.cwd(), 'projects.json');
const globalListPath = path.join(
  process.env.HOME || process.env.USERPROFILE || '.',
  '.security-scan-projects.json'
);

// Use local if exists, otherwise global
const defaultListPath = fs.existsSync(localListPath) ? localListPath : globalListPath;

if (showHelp) {
  console.log(`
${colors.bold}Multi-Project Security Scanner${colors.reset}
${colors.dim}Scan multiple Node.js projects at once${colors.reset}

${colors.bold}Usage:${colors.reset}
  node scripts/scan-all.js <directory> [options]
  node scripts/scan-all.js --from-list [options]

${colors.bold}Arguments:${colors.reset}
  directory              Directory containing projects (default: current)

${colors.bold}Scanning Options:${colors.reset}
  --depth <n>            How deep to search for projects (default: 2)
  --parallel             Scan projects in parallel (faster)
  --json                 Output results as JSON
  --verbose, -v          Show detailed output

${colors.bold}Projects List:${colors.reset}
  --from-list            Scan projects from saved list
  --list <path>          Use custom list file
  --add <path>           Add a project to the list
  --remove <path>        Remove a project from the list
  --show-list            Show all projects in the list

${colors.bold}Other:${colors.reset}
  --help, -h             Show this help

${colors.bold}Examples:${colors.reset}
  ${colors.cyan}# Scan a directory${colors.reset}
  node scripts/scan-all.js ~/projects
  node scripts/scan-all.js ~/code --depth 3

  ${colors.cyan}# Use a projects list${colors.reset}
  node scripts/scan-all.js --add ~/projects/my-app
  node scripts/scan-all.js --add ~/code/another-project
  node scripts/scan-all.js --from-list
  node scripts/scan-all.js --show-list

  ${colors.cyan}# Parallel with JSON output${colors.reset}
  node scripts/scan-all.js --from-list --parallel --json

${colors.bold}Projects List Location:${colors.reset}
  1. ./projects.json (local, checked first)
  2. ~/.security-scan-projects.json (global fallback)
  Custom: --list /path/to/list.json
`);
  process.exit(0);
}

/**
 * Load projects list from file
 */
function loadProjectsList(listFile) {
  const file = listFile || defaultListPath;
  
  if (!fs.existsSync(file)) {
    return { projects: [] };
  }
  
  try {
    const content = fs.readFileSync(file, 'utf8');
    return JSON.parse(content);
  } catch (error) {
    console.error(`${colors.red}Error loading projects list: ${error.message}${colors.reset}`);
    return { projects: [] };
  }
}

/**
 * Save projects list to file
 */
function saveProjectsList(data, listFile) {
  const file = listFile || defaultListPath;
  
  try {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
    return true;
  } catch (error) {
    console.error(`${colors.red}Error saving projects list: ${error.message}${colors.reset}`);
    return false;
  }
}

/**
 * Expand ~ to home directory
 */
function expandPath(p) {
  if (p.startsWith('~/')) {
    return path.join(process.env.HOME || process.env.USERPROFILE || '', p.slice(2));
  }
  return path.resolve(p);
}

// Handle --add
if (addProject) {
  const list = loadProjectsList(listPath);
  const projectPath = expandPath(addProject);
  
  if (!fs.existsSync(projectPath)) {
    console.error(`${colors.red}Error: Directory not found: ${projectPath}${colors.reset}`);
    process.exit(2);
  }
  
  if (!fs.existsSync(path.join(projectPath, 'package.json'))) {
    console.error(`${colors.red}Error: No package.json found in: ${projectPath}${colors.reset}`);
    process.exit(2);
  }
  
  if (list.projects.includes(projectPath)) {
    console.log(`${colors.yellow}Project already in list: ${projectPath}${colors.reset}`);
  } else {
    list.projects.push(projectPath);
    saveProjectsList(list, listPath);
    console.log(`${colors.green}✓ Added: ${projectPath}${colors.reset}`);
    console.log(`${colors.dim}Total projects: ${list.projects.length}${colors.reset}`);
  }
  process.exit(0);
}

// Handle --add-all (bulk add from directory)
if (addAll) {
  const list = loadProjectsList(listPath);
  const dir = expandPath(addAll);
  
  if (!fs.existsSync(dir)) {
    console.error(`${colors.red}Error: Directory not found: ${dir}${colors.reset}`);
    process.exit(2);
  }
  
  console.log(`${colors.cyan}Finding projects in: ${dir}${colors.reset}`);
  const projects = findProjects(dir);
  
  let added = 0;
  for (const projectPath of projects) {
    if (!list.projects.includes(projectPath)) {
      list.projects.push(projectPath);
      console.log(`  ${colors.green}+${colors.reset} ${path.basename(projectPath)}`);
      added++;
    }
  }
  
  if (added > 0) {
    saveProjectsList(list, listPath);
    console.log(`\n${colors.green}✓ Added ${added} project(s)${colors.reset}`);
  } else {
    console.log(`${colors.yellow}No new projects to add${colors.reset}`);
  }
  console.log(`${colors.dim}Total in list: ${list.projects.length}${colors.reset}`);
  process.exit(0);
}

// Handle --remove
if (removeProject) {
  const list = loadProjectsList(listPath);
  const projectPath = expandPath(removeProject);
  
  const index = list.projects.findIndex(p => p === projectPath || expandPath(p) === projectPath);
  
  if (index === -1) {
    console.error(`${colors.yellow}Project not in list: ${projectPath}${colors.reset}`);
  } else {
    list.projects.splice(index, 1);
    saveProjectsList(list, listPath);
    console.log(`${colors.green}✓ Removed: ${projectPath}${colors.reset}`);
    console.log(`${colors.dim}Total projects: ${list.projects.length}${colors.reset}`);
  }
  process.exit(0);
}

// Handle --show-list
if (showList) {
  const list = loadProjectsList(listPath);
  const file = listPath || defaultListPath;
  
  console.log(`\n${colors.bold}Projects List${colors.reset}`);
  console.log(`${colors.dim}File: ${file}${colors.reset}\n`);
  
  if (list.projects.length === 0) {
    console.log(`${colors.yellow}No projects in list.${colors.reset}`);
    console.log(`${colors.dim}Add projects with: --add <path>${colors.reset}`);
  } else {
    console.log(`${colors.cyan}${list.projects.length} project(s):${colors.reset}\n`);
    for (const p of list.projects) {
      const exists = fs.existsSync(expandPath(p));
      const icon = exists ? colors.green + '✓' : colors.red + '✗';
      console.log(`  ${icon}${colors.reset} ${p}`);
    }
  }
  console.log();
  process.exit(0);
}

/**
 * Find all Node.js projects (directories with package.json)
 */
function findProjects(dir, depth = 0) {
  const projects = [];
  
  if (depth > maxDepth) return projects;
  
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    
    // Check if this directory is a project
    const hasPackageJson = entries.some(e => e.name === 'package.json' && e.isFile());
    
    if (hasPackageJson) {
      projects.push(dir);
      // Don't recurse into node_modules of found projects
      return projects;
    }
    
    // Recurse into subdirectories
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (entry.name === 'node_modules') continue;
      if (entry.name === '.git') continue;
      if (entry.name.startsWith('.')) continue;
      
      const subDir = path.join(dir, entry.name);
      projects.push(...findProjects(subDir, depth + 1));
    }
  } catch (error) {
    // Permission denied or other errors
    if (verbose) {
      console.error(`${colors.dim}Could not read: ${dir}${colors.reset}`);
    }
  }
  
  return projects;
}

/**
 * Run security scan on a single project
 */
function scanProject(projectPath) {
  return new Promise((resolve) => {
    const scannerPath = path.join(__dirname, 'security-scan.js');
    
    // Check if scanner exists in project or use this one
    const projectScanner = path.join(projectPath, 'scripts', 'security-scan.js');
    const dbPath = path.join(projectPath, 'security', 'compromised-packages.json');
    
    // Determine which scanner and database to use
    let scanner = scannerPath;
    let args = ['--json'];
    
    // If project has its own scanner and database, use those
    if (fs.existsSync(projectScanner) && fs.existsSync(dbPath)) {
      scanner = projectScanner;
    }
    
    const proc = spawn('node', [scanner, ...args], {
      cwd: projectPath,
      env: { ...process.env, FORCE_COLOR: '0' }
    });
    
    let stdout = '';
    let stderr = '';
    
    proc.stdout.on('data', (data) => { stdout += data.toString(); });
    proc.stderr.on('data', (data) => { stderr += data.toString(); });
    
    proc.on('close', (code) => {
      let result = {
        project: projectPath,
        name: path.basename(projectPath),
        exitCode: code,
        error: null,
        packagesScanned: 0,
        totalIssues: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      };
      
      try {
        const parsed = JSON.parse(stdout);
        result.packagesScanned = parsed.packagesScanned || 0;
        result.totalIssues = parsed.totalIssues || 0;
        result.critical = parsed.results?.critical?.length || 0;
        result.high = parsed.results?.high?.length || 0;
        result.medium = parsed.results?.medium?.length || 0;
        result.low = parsed.results?.low?.length || 0;
        result.issues = parsed.results;
      } catch (e) {
        if (code === 2) {
          result.error = 'Configuration error';
        } else if (stderr) {
          result.error = stderr.trim();
        }
      }
      
      resolve(result);
    });
    
    proc.on('error', (error) => {
      resolve({
        project: projectPath,
        name: path.basename(projectPath),
        exitCode: 2,
        error: error.message,
        packagesScanned: 0,
        totalIssues: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      });
    });
  });
}

/**
 * Format a result row
 */
function formatResult(result) {
  const status = result.error 
    ? `${colors.yellow}⚠ Error${colors.reset}`
    : result.totalIssues === 0 
      ? `${colors.green}✓ Clean${colors.reset}`
      : `${colors.red}✗ ${result.totalIssues} issues${colors.reset}`;
  
  let details = '';
  if (result.totalIssues > 0) {
    const parts = [];
    if (result.critical > 0) parts.push(`${colors.red}${result.critical} critical${colors.reset}`);
    if (result.high > 0) parts.push(`${colors.yellow}${result.high} high${colors.reset}`);
    if (result.medium > 0) parts.push(`${result.medium} medium`);
    if (result.low > 0) parts.push(`${result.low} low`);
    details = ` (${parts.join(', ')})`;
  }
  
  return `  ${status} ${colors.bold}${result.name}${colors.reset}${details}`;
}

/**
 * Main function
 */
async function main() {
  let projects = [];
  
  // If using projects list
  if (fromList) {
    const list = loadProjectsList(listPath);
    
    if (list.projects.length === 0) {
      console.log(`${colors.yellow}No projects in list.${colors.reset}`);
      console.log(`${colors.dim}Add projects with: --add <path>${colors.reset}`);
      process.exit(0);
    }
    
    console.log(`\n${colors.bold}🔍 Scanning projects from list...${colors.reset}`);
    console.log(`${colors.dim}Projects: ${list.projects.length}${colors.reset}\n`);
    
    // Expand paths and filter existing
    for (const p of list.projects) {
      const expanded = expandPath(p);
      if (fs.existsSync(expanded) && fs.existsSync(path.join(expanded, 'package.json'))) {
        projects.push(expanded);
      } else {
        console.log(`${colors.yellow}⚠ Skipping (not found): ${p}${colors.reset}`);
      }
    }
  } else {
    // Scan directory
    const resolvedDir = path.resolve(targetDir);
    
    if (!fs.existsSync(resolvedDir)) {
      console.error(`${colors.red}Error: Directory not found: ${resolvedDir}${colors.reset}`);
      process.exit(2);
    }
    
    console.log(`\n${colors.bold}🔍 Scanning for Node.js projects...${colors.reset}`);
    console.log(`${colors.dim}Directory: ${resolvedDir}${colors.reset}`);
    console.log(`${colors.dim}Max depth: ${maxDepth}${colors.reset}\n`);
    
    // Find all projects
    projects = findProjects(resolvedDir);
  }
  
  if (projects.length === 0) {
    console.log(`${colors.yellow}No Node.js projects found.${colors.reset}`);
    process.exit(0);
  }
  
  console.log(`${colors.cyan}Found ${projects.length} project(s)${colors.reset}\n`);
  
  // Scan all projects
  let results;
  
  if (parallel) {
    console.log(`${colors.dim}Scanning in parallel...${colors.reset}\n`);
    results = await Promise.all(projects.map(scanProject));
  } else {
    results = [];
    for (const project of projects) {
      if (verbose) {
        console.log(`${colors.dim}Scanning: ${project}${colors.reset}`);
      }
      const result = await scanProject(project);
      results.push(result);
      
      if (!jsonOutput) {
        console.log(formatResult(result));
      }
    }
  }
  
  // If parallel, print all results now
  if (parallel && !jsonOutput) {
    for (const result of results) {
      console.log(formatResult(result));
    }
  }
  
  // Calculate totals
  const totals = {
    projects: results.length,
    clean: results.filter(r => r.totalIssues === 0 && !r.error).length,
    withIssues: results.filter(r => r.totalIssues > 0).length,
    errors: results.filter(r => r.error).length,
    packagesScanned: results.reduce((sum, r) => sum + r.packagesScanned, 0),
    totalIssues: results.reduce((sum, r) => sum + r.totalIssues, 0),
    critical: results.reduce((sum, r) => sum + r.critical, 0),
    high: results.reduce((sum, r) => sum + r.high, 0),
    medium: results.reduce((sum, r) => sum + r.medium, 0),
    low: results.reduce((sum, r) => sum + r.low, 0),
  };
  
  // Output
  if (jsonOutput) {
    console.log(JSON.stringify({ totals, results }, null, 2));
  } else {
    const separator = '━'.repeat(60);
    console.log(`\n${separator}`);
    console.log(`  ${colors.bold}📊 SUMMARY${colors.reset}`);
    console.log(separator);
    console.log(`  Projects scanned:  ${totals.projects}`);
    console.log(`  ${colors.green}Clean:${colors.reset}             ${totals.clean}`);
    console.log(`  ${colors.red}With issues:${colors.reset}       ${totals.withIssues}`);
    if (totals.errors > 0) {
      console.log(`  ${colors.yellow}Errors:${colors.reset}            ${totals.errors}`);
    }
    console.log(`  Packages scanned:  ${totals.packagesScanned}`);
    console.log();
    console.log(`  ${colors.bold}Issues by severity:${colors.reset}`);
    console.log(`    ${colors.red}Critical:${colors.reset} ${totals.critical}`);
    console.log(`    ${colors.yellow}High:${colors.reset}     ${totals.high}`);
    console.log(`    Medium:   ${totals.medium}`);
    console.log(`    Low:      ${totals.low}`);
    console.log(separator);
    
    if (totals.totalIssues > 0) {
      console.log(`\n${colors.red}❌ ${totals.totalIssues} total issues found across ${totals.withIssues} project(s)${colors.reset}`);
      
      // Show which projects have issues
      const projectsWithIssues = results.filter(r => r.totalIssues > 0);
      console.log(`\n${colors.bold}Projects with issues:${colors.reset}`);
      for (const p of projectsWithIssues) {
        console.log(`  • ${p.name}: ${p.critical} critical, ${p.high} high`);
      }
    } else {
      console.log(`\n${colors.green}✅ All projects are clean!${colors.reset}`);
    }
    console.log();
  }
  
  // Exit code
  if (totals.critical > 0 || totals.high > 0) {
    process.exit(1);
  }
  process.exit(0);
}

main().catch(error => {
  console.error(`${colors.red}Error: ${error.message}${colors.reset}`);
  process.exit(2);
});

