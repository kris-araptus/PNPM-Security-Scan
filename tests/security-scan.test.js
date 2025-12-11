/**
 * Unit Tests for npm Security Scanner
 * 
 * Run with: node --test tests/security-scan.test.js
 * Or: pnpm test
 * 
 * Uses Node.js built-in test runner (Node 18+)
 */

const { describe, it, before, after, mock } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

// Paths
const ROOT_DIR = path.join(__dirname, '..');
const SCANNER_PATH = path.join(ROOT_DIR, 'scripts', 'security-scan.js');
const DB_PATH = path.join(ROOT_DIR, 'security', 'compromised-packages.json');
const TEST_DIR = path.join(__dirname, 'fixtures');

// Helper: Run scanner and capture output
function runScanner(args = [], cwd = ROOT_DIR) {
  return new Promise((resolve, reject) => {
    const proc = spawn('node', [SCANNER_PATH, ...args], {
      cwd,
      env: { ...process.env, FORCE_COLOR: '0' }
    });
    
    let stdout = '';
    let stderr = '';
    
    proc.stdout.on('data', (data) => { stdout += data.toString(); });
    proc.stderr.on('data', (data) => { stderr += data.toString(); });
    
    proc.on('close', (code) => {
      resolve({ code, stdout, stderr });
    });
    
    proc.on('error', reject);
  });
}

// Helper: Create test fixture
function createFixture(name, packageJson) {
  const dir = path.join(TEST_DIR, name);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'package.json'),
    JSON.stringify(packageJson, null, 2)
  );
  
  // Copy security database to fixture
  const securityDir = path.join(dir, 'security');
  fs.mkdirSync(securityDir, { recursive: true });
  fs.copyFileSync(DB_PATH, path.join(securityDir, 'compromised-packages.json'));
  
  // Copy scanner script
  const scriptsDir = path.join(dir, 'scripts');
  fs.mkdirSync(scriptsDir, { recursive: true });
  fs.copyFileSync(SCANNER_PATH, path.join(scriptsDir, 'security-scan.js'));
  
  return dir;
}

// Helper: Clean up fixture
function removeFixture(name) {
  const dir = path.join(TEST_DIR, name);
  if (fs.existsSync(dir)) {
    fs.rmSync(dir, { recursive: true });
  }
}

// ============================================
// Database Tests
// ============================================

describe('Threat Database', () => {
  let db;
  
  before(() => {
    const content = fs.readFileSync(DB_PATH, 'utf8');
    db = JSON.parse(content);
  });
  
  it('should be valid JSON', () => {
    assert.ok(db, 'Database should parse as JSON');
  });
  
  it('should have required fields', () => {
    assert.ok(db.version, 'Should have version');
    assert.ok(db.lastUpdated, 'Should have lastUpdated');
    assert.ok(db.campaigns, 'Should have campaigns');
    assert.ok(db.knownMalicious, 'Should have knownMalicious');
    assert.ok(db.trustedPackages, 'Should have trustedPackages');
  });
  
  it('should have valid version format', () => {
    assert.match(db.version, /^\d+\.\d+\.\d+$/, 'Version should be semver');
  });
  
  it('should have valid date format', () => {
    assert.match(db.lastUpdated, /^\d{4}-\d{2}-\d{2}$/, 'Date should be YYYY-MM-DD');
  });
  
  it('should have campaigns with required fields', () => {
    for (const [id, campaign] of Object.entries(db.campaigns)) {
      assert.ok(campaign.name, `Campaign ${id} should have name`);
      assert.ok(campaign.severity, `Campaign ${id} should have severity`);
      assert.ok(['critical', 'high', 'medium', 'low'].includes(campaign.severity),
        `Campaign ${id} severity should be valid`);
    }
  });
  
  it('should have known malicious packages as arrays', () => {
    assert.ok(Array.isArray(db.knownMalicious.confirmed), 'confirmed should be array');
    assert.ok(Array.isArray(db.knownMalicious.typosquatting), 'typosquatting should be array');
    assert.ok(Array.isArray(db.knownMalicious.credentialTheft), 'credentialTheft should be array');
  });
  
  it('should have trusted packages as array', () => {
    assert.ok(Array.isArray(db.trustedPackages.packages), 'trustedPackages.packages should be array');
  });
  
  it('should have at least 40 known malicious packages', () => {
    const total = 
      db.knownMalicious.confirmed.length +
      db.knownMalicious.typosquatting.length +
      db.knownMalicious.credentialTheft.length;
    assert.ok(total >= 40, `Should have at least 40 malicious packages, got ${total}`);
  });
});

// ============================================
// CLI Tests
// ============================================

describe('CLI Interface', () => {
  it('should show help with --help', async () => {
    const { code, stdout } = await runScanner(['--help']);
    assert.strictEqual(code, 0, 'Should exit with code 0');
    assert.ok(stdout.includes('PNPM Security Scanner'), 'Should show title');
    assert.ok(stdout.includes('--verbose'), 'Should show verbose option');
    assert.ok(stdout.includes('--json'), 'Should show json option');
    assert.ok(stdout.includes('--strict'), 'Should show strict option');
  });
  
  it('should show help with -h', async () => {
    const { code, stdout } = await runScanner(['-h']);
    assert.strictEqual(code, 0, 'Should exit with code 0');
    assert.ok(stdout.includes('PNPM Security Scanner'), 'Should show title');
  });
  
  it('should accept --verbose flag', async () => {
    const { code, stdout } = await runScanner(['--verbose']);
    assert.strictEqual(code, 0, 'Should exit successfully');
    assert.ok(stdout.includes('Database loaded from'), 'Should show database path in verbose');
  });
  
  it('should accept -v flag', async () => {
    const { code, stdout } = await runScanner(['-v']);
    assert.strictEqual(code, 0, 'Should exit successfully');
    assert.ok(stdout.includes('Database loaded from'), 'Should show database path');
  });
  
  it('should output valid JSON with --json', async () => {
    const { code, stdout } = await runScanner(['--json']);
    assert.strictEqual(code, 0, 'Should exit successfully');
    
    const result = JSON.parse(stdout);
    assert.ok(result.timestamp, 'Should have timestamp');
    assert.ok(typeof result.packagesScanned === 'number', 'Should have packagesScanned');
    assert.ok(typeof result.totalIssues === 'number', 'Should have totalIssues');
    assert.ok(result.results, 'Should have results');
    assert.ok(Array.isArray(result.results.critical), 'Should have critical array');
    assert.ok(Array.isArray(result.results.high), 'Should have high array');
    assert.ok(Array.isArray(result.results.medium), 'Should have medium array');
    assert.ok(Array.isArray(result.results.low), 'Should have low array');
  });
});

// ============================================
// Scanning Tests - Clean Project
// ============================================

describe('Scanning Clean Project', () => {
  const fixtureName = 'clean-project';
  let fixtureDir;
  
  before(() => {
    fixtureDir = createFixture(fixtureName, {
      name: 'test-clean-project',
      version: '1.0.0',
      dependencies: {
        'lodash': '^4.17.21',
        'express': '^4.18.2'
      },
      devDependencies: {
        'typescript': '^5.0.0',
        'jest': '^29.0.0'
      }
    });
  });
  
  after(() => {
    removeFixture(fixtureName);
  });
  
  it('should exit with code 0 for clean project', async () => {
    const { code } = await runScanner([], fixtureDir);
    assert.strictEqual(code, 0, 'Should exit with code 0');
  });
  
  it('should report 0 issues for clean project', async () => {
    const { stdout } = await runScanner(['--json'], fixtureDir);
    const result = JSON.parse(stdout);
    assert.strictEqual(result.totalIssues, 0, 'Should have 0 issues');
  });
  
  it('should scan all dependencies', async () => {
    const { stdout } = await runScanner(['--json'], fixtureDir);
    const result = JSON.parse(stdout);
    assert.strictEqual(result.packagesScanned, 4, 'Should scan 4 packages');
  });
  
  it('should show success message', async () => {
    const { stdout } = await runScanner([], fixtureDir);
    assert.ok(stdout.includes('No security issues detected'), 'Should show success');
    assert.ok(stdout.includes('Security scan PASSED'), 'Should show PASSED');
  });
});

// ============================================
// Scanning Tests - Malicious Package
// ============================================

describe('Scanning Project with Malicious Package', () => {
  const fixtureName = 'malicious-project';
  let fixtureDir;
  
  before(() => {
    fixtureDir = createFixture(fixtureName, {
      name: 'test-malicious-project',
      version: '1.0.0',
      dependencies: {
        'lodash': '^4.17.21',
        'event-stream': '^4.0.0'  // Known malicious
      }
    });
  });
  
  after(() => {
    removeFixture(fixtureName);
  });
  
  it('should exit with code 1 for malicious package', async () => {
    const { code } = await runScanner([], fixtureDir);
    assert.strictEqual(code, 1, 'Should exit with code 1');
  });
  
  it('should detect malicious package', async () => {
    const { stdout } = await runScanner(['--json'], fixtureDir);
    const result = JSON.parse(stdout);
    assert.ok(result.totalIssues > 0, 'Should find issues');
    assert.ok(result.results.critical.length > 0, 'Should have critical issues');
  });
  
  it('should identify the malicious package', async () => {
    const { stdout } = await runScanner(['--json'], fixtureDir);
    const result = JSON.parse(stdout);
    const found = result.results.critical.some(i => i.package === 'event-stream');
    assert.ok(found, 'Should identify event-stream as malicious');
  });
  
  it('should show FAILED message', async () => {
    const { stdout } = await runScanner([], fixtureDir);
    assert.ok(stdout.includes('Security scan FAILED'), 'Should show FAILED');
  });
});

// ============================================
// Scanning Tests - Typosquatting
// ============================================

describe('Scanning Project with Typosquatting Package', () => {
  const fixtureName = 'typosquat-project';
  let fixtureDir;
  
  before(() => {
    fixtureDir = createFixture(fixtureName, {
      name: 'test-typosquat-project',
      version: '1.0.0',
      dependencies: {
        'lodash': '^4.17.21',
        'loadash': '^1.0.0'  // Typosquatting variant
      }
    });
  });
  
  after(() => {
    removeFixture(fixtureName);
  });
  
  it('should detect typosquatting package', async () => {
    const { code, stdout } = await runScanner(['--json'], fixtureDir);
    assert.strictEqual(code, 1, 'Should exit with code 1');
    
    const result = JSON.parse(stdout);
    const found = result.results.critical.some(i => 
      i.package === 'loadash' && i.type === 'Typosquatting'
    );
    assert.ok(found, 'Should identify loadash as typosquatting');
  });
});

// ============================================
// Scanning Tests - Trusted Packages
// ============================================

describe('Trusted Packages', () => {
  const fixtureName = 'trusted-project';
  let fixtureDir;
  
  before(() => {
    fixtureDir = createFixture(fixtureName, {
      name: 'test-trusted-project',
      version: '1.0.0',
      dependencies: {
        '@types/node': '^20.0.0',
        '@astrojs/node': '^1.0.0',
        'typescript': '^5.0.0'
      }
    });
  });
  
  after(() => {
    removeFixture(fixtureName);
  });
  
  it('should recognize trusted packages', async () => {
    const { code, stdout } = await runScanner(['--verbose'], fixtureDir);
    assert.strictEqual(code, 0, 'Should exit with code 0');
    assert.ok(stdout.includes('Trusted package'), 'Should show trusted packages');
  });
  
  it('should not flag trusted packages as issues', async () => {
    const { stdout } = await runScanner(['--json'], fixtureDir);
    const result = JSON.parse(stdout);
    assert.strictEqual(result.totalIssues, 0, 'Should have 0 issues');
  });
});

// ============================================
// Scanning Tests - Strict Mode
// ============================================

describe('Strict Mode', () => {
  const fixtureName = 'strict-project';
  let fixtureDir;
  
  before(() => {
    fixtureDir = createFixture(fixtureName, {
      name: 'test-strict-project',
      version: '1.0.0',
      dependencies: {
        'lodash': '^4.17.21'
      }
    });
  });
  
  after(() => {
    removeFixture(fixtureName);
  });
  
  it('should pass strict mode with clean project', async () => {
    const { code } = await runScanner(['--strict'], fixtureDir);
    assert.strictEqual(code, 0, 'Should exit with code 0 in strict mode');
  });
});

// ============================================
// Scanning Tests - Campaign Detection
// ============================================

describe('Campaign Detection', () => {
  const fixtureName = 'campaign-project';
  let fixtureDir;
  
  before(() => {
    fixtureDir = createFixture(fixtureName, {
      name: 'test-campaign-project',
      version: '1.0.0',
      dependencies: {
        '@ctrl/tinycolor': '^3.6.1'  // Shai-Hulud campaign
      }
    });
  });
  
  after(() => {
    removeFixture(fixtureName);
  });
  
  it('should detect campaign package', async () => {
    const { code, stdout } = await runScanner(['--json'], fixtureDir);
    assert.strictEqual(code, 1, 'Should exit with code 1');
    
    const result = JSON.parse(stdout);
    assert.ok(result.totalIssues > 0, 'Should find issues');
  });
  
  it('should identify campaign name', async () => {
    const { stdout } = await runScanner([], fixtureDir);
    assert.ok(
      stdout.includes('Shai-Hulud') || stdout.includes('Confirmed Malicious'),
      'Should mention Shai-Hulud campaign or mark as malicious'
    );
  });
});

// ============================================
// Edge Cases
// ============================================

describe('Edge Cases', () => {
  it('should handle empty dependencies', async () => {
    const fixtureName = 'empty-deps';
    const fixtureDir = createFixture(fixtureName, {
      name: 'test-empty',
      version: '1.0.0'
    });
    
    try {
      const { code, stdout } = await runScanner([], fixtureDir);
      assert.strictEqual(code, 0, 'Should exit with code 0');
      assert.ok(stdout.includes('No dependencies found'), 'Should note no dependencies');
    } finally {
      removeFixture(fixtureName);
    }
  });
  
  it('should traverse up to find package.json', async () => {
    // Scanner correctly traverses up directory tree to find package.json
    // This test verifies that behavior works as expected
    const emptyDir = path.join(TEST_DIR, 'nested', 'deep', 'folder');
    fs.mkdirSync(emptyDir, { recursive: true });
    
    // Copy scanner files
    const scriptsDir = path.join(emptyDir, 'scripts');
    fs.mkdirSync(scriptsDir, { recursive: true });
    fs.copyFileSync(SCANNER_PATH, path.join(scriptsDir, 'security-scan.js'));
    
    const securityDir = path.join(emptyDir, 'security');
    fs.mkdirSync(securityDir, { recursive: true });
    fs.copyFileSync(DB_PATH, path.join(securityDir, 'compromised-packages.json'));
    
    try {
      // Scanner should traverse up and find ROOT_DIR's package.json
      const { code } = await runScanner([], emptyDir);
      // Should succeed since it finds parent package.json
      assert.strictEqual(code, 0, 'Should find package.json by traversing up');
    } finally {
      fs.rmSync(path.join(TEST_DIR, 'nested'), { recursive: true });
    }
  });
  
  it('should scan peerDependencies', async () => {
    const fixtureName = 'peer-deps';
    const fixtureDir = createFixture(fixtureName, {
      name: 'test-peer',
      version: '1.0.0',
      peerDependencies: {
        'react': '^18.0.0'
      }
    });
    
    try {
      const { stdout } = await runScanner(['--json'], fixtureDir);
      const result = JSON.parse(stdout);
      assert.strictEqual(result.packagesScanned, 1, 'Should scan peer dependencies');
    } finally {
      removeFixture(fixtureName);
    }
  });
  
  it('should scan optionalDependencies', async () => {
    const fixtureName = 'optional-deps';
    const fixtureDir = createFixture(fixtureName, {
      name: 'test-optional',
      version: '1.0.0',
      optionalDependencies: {
        'fsevents': '^2.3.0'
      }
    });
    
    try {
      const { stdout } = await runScanner(['--json'], fixtureDir);
      const result = JSON.parse(stdout);
      assert.strictEqual(result.packagesScanned, 1, 'Should scan optional dependencies');
    } finally {
      removeFixture(fixtureName);
    }
  });
});

// ============================================
// JSON Output Format
// ============================================

describe('JSON Output Format', () => {
  it('should have valid ISO timestamp', async () => {
    const { stdout } = await runScanner(['--json']);
    const result = JSON.parse(stdout);
    const date = new Date(result.timestamp);
    assert.ok(!isNaN(date.getTime()), 'Timestamp should be valid ISO date');
  });
  
  it('should have correct structure for issues', async () => {
    const fixtureName = 'json-format';
    const fixtureDir = createFixture(fixtureName, {
      name: 'test-json',
      version: '1.0.0',
      dependencies: {
        'event-stream': '^4.0.0'
      }
    });
    
    try {
      const { stdout } = await runScanner(['--json'], fixtureDir);
      const result = JSON.parse(stdout);
      
      assert.ok(result.results.critical.length > 0, 'Should have critical issues');
      
      const issue = result.results.critical[0];
      assert.ok(issue.package, 'Issue should have package');
      assert.ok(issue.version, 'Issue should have version');
      assert.ok(issue.severity, 'Issue should have severity');
      assert.ok(issue.type, 'Issue should have type');
      assert.ok(issue.reason, 'Issue should have reason');
      assert.ok(issue.action, 'Issue should have action');
    } finally {
      removeFixture(fixtureName);
    }
  });
});

// ============================================
// Pattern Matching
// ============================================

describe('Pattern Matching', () => {
  it('should match scoped package wildcards', async () => {
    const fixtureName = 'scoped-packages';
    const fixtureDir = createFixture(fixtureName, {
      name: 'test-scoped',
      version: '1.0.0',
      dependencies: {
        '@types/node': '^20.0.0',
        '@types/react': '^18.0.0',
        '@astrojs/node': '^1.0.0',
        '@babel/core': '^7.0.0'
      }
    });
    
    try {
      const { stdout } = await runScanner(['--verbose'], fixtureDir);
      // @types/* and @astrojs/* should be trusted
      const trustedCount = (stdout.match(/Trusted/g) || []).length;
      assert.ok(trustedCount >= 3, 'Should recognize multiple trusted scoped packages');
    } finally {
      removeFixture(fixtureName);
    }
  });
});

// Run cleanup before tests
before(() => {
  if (fs.existsSync(TEST_DIR)) {
    fs.rmSync(TEST_DIR, { recursive: true });
  }
  fs.mkdirSync(TEST_DIR, { recursive: true });
});

// Cleanup after all tests
after(() => {
  if (fs.existsSync(TEST_DIR)) {
    fs.rmSync(TEST_DIR, { recursive: true });
  }
});

