import type { ScanResult, ScanIssue, ThreatDatabase } from './types';
import threatDb from './threat-db.json';

const db = threatDb as ThreatDatabase;

/**
 * Parse package.json content
 */
function parsePackageJson(content: string): Record<string, string> {
  try {
    const pkg = JSON.parse(content);
    return {
      ...pkg.dependencies,
      ...pkg.devDependencies,
      ...pkg.peerDependencies,
      ...pkg.optionalDependencies,
    };
  } catch {
    throw new Error('Invalid package.json format');
  }
}

/**
 * Parse pnpm-lock.yaml content (simplified parser)
 */
function parsePnpmLock(content: string): Map<string, { version: string; isTransitive: boolean }> {
  const packages = new Map<string, { version: string; isTransitive: boolean }>();
  const lines = content.split('\n');
  
  let inPackages = false;
  
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    
    if (trimmed === 'packages:') {
      inPackages = true;
      continue;
    }
    
    if (inPackages && !line.startsWith(' ') && !line.startsWith('\t') && trimmed !== '') {
      if (!trimmed.startsWith('/') && !trimmed.startsWith("'")) {
        inPackages = false;
        continue;
      }
    }
    
    if (inPackages) {
      const packageMatch = trimmed.match(/^['"]?\/?((?:@[^@/]+\/)?[^@:]+)@([^:']+)['"]?:?\s*$/);
      if (packageMatch) {
        const [, name, version] = packageMatch;
        if (!packages.has(name)) {
          packages.set(name, {
            version: version.replace(/['"]/g, ''),
            isTransitive: true,
          });
        }
      }
    }
  }
  
  return packages;
}

/**
 * Parse package-lock.json content
 */
function parseNpmLock(content: string): Map<string, { version: string; isTransitive: boolean }> {
  const packages = new Map<string, { version: string; isTransitive: boolean }>();
  
  try {
    const lockfile = JSON.parse(content);
    
    if (lockfile.packages) {
      for (const [pkgPath, pkgInfo] of Object.entries(lockfile.packages)) {
        if (pkgPath === '') continue;
        
        const match = pkgPath.match(/node_modules\/((?:@[^/]+\/)?[^/]+)$/);
        if (match) {
          const name = match[1];
          packages.set(name, {
            version: (pkgInfo as any).version || 'unknown',
            isTransitive: true,
          });
        }
      }
    }
    
    if (lockfile.dependencies) {
      const parseDeps = (deps: any) => {
        for (const [name, info] of Object.entries(deps)) {
          packages.set(name, {
            version: (info as any).version || 'unknown',
            isTransitive: true,
          });
          if ((info as any).dependencies) {
            parseDeps((info as any).dependencies);
          }
        }
      };
      parseDeps(lockfile.dependencies);
    }
  } catch {
    throw new Error('Invalid package-lock.json format');
  }
  
  return packages;
}

/**
 * Parse yarn.lock content
 */
function parseYarnLock(content: string): Map<string, { version: string; isTransitive: boolean }> {
  const packages = new Map<string, { version: string; isTransitive: boolean }>();
  const lines = content.split('\n');
  
  let currentPackages: string[] = [];
  
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    
    if (!line.startsWith(' ') && !line.startsWith('\t')) {
      const pkgMatches = trimmed.matchAll(/["']?((?:@[^@,\s]+\/)?[^@,\s"']+)@[^,:\s"']+["']?/g);
      currentPackages = [];
      for (const match of pkgMatches) {
        if (match[1]) currentPackages.push(match[1]);
      }
    }
    
    if (line.startsWith('  version') && currentPackages.length > 0) {
      const versionMatch = trimmed.match(/version\s+["']?([^"'\s]+)["']?/);
      if (versionMatch) {
        for (const pkgName of currentPackages) {
          if (!packages.has(pkgName)) {
            packages.set(pkgName, {
              version: versionMatch[1],
              isTransitive: true,
            });
          }
        }
      }
    }
  }
  
  return packages;
}

/**
 * Check if a package matches a pattern
 */
function matchesPattern(packageName: string, pattern: string): boolean {
  if (pattern.endsWith('/*')) {
    const scope = pattern.slice(0, -2);
    return packageName.startsWith(scope + '/');
  }
  return packageName === pattern;
}

/**
 * Check if a package is trusted
 */
function isTrusted(packageName: string): boolean {
  const trusted = db.trustedPackages?.packages || [];
  return trusted.some(pattern => matchesPattern(packageName, pattern));
}

/**
 * Check a package against the threat database
 */
function checkPackage(
  packageName: string,
  version: string,
  isDirect: boolean,
  isTransitive: boolean,
  dependencyChain: string[] = []
): ScanIssue | null {
  if (isTrusted(packageName)) return null;
  
  const malicious = db.knownMalicious || {};
  const baseIssue = {
    package: packageName,
    version,
    isDirect,
    isTransitive,
    dependencyChain,
  };
  
  if (malicious.confirmed?.includes(packageName)) {
    return {
      ...baseIssue,
      severity: 'critical',
      type: 'Confirmed Malicious',
      reason: 'This package has been confirmed as malicious',
      action: 'REMOVE IMMEDIATELY',
    };
  }
  
  if (malicious.typosquatting?.includes(packageName)) {
    return {
      ...baseIssue,
      severity: 'critical',
      type: 'Typosquatting',
      reason: 'This package name is a typosquatting variant of a popular package',
      action: 'REMOVE IMMEDIATELY - Check you have the correct package name',
    };
  }
  
  if (malicious.credentialTheft?.includes(packageName)) {
    return {
      ...baseIssue,
      severity: 'critical',
      type: 'Credential Theft',
      reason: 'This package has been found to steal credentials',
      action: 'REMOVE IMMEDIATELY - Rotate all credentials',
    };
  }
  
  if (malicious.cryptoMalware?.includes(packageName)) {
    return {
      ...baseIssue,
      severity: 'critical',
      type: 'Crypto Malware',
      reason: 'This package contains cryptocurrency mining or wallet-stealing malware',
      action: 'REMOVE IMMEDIATELY - Check for unauthorized transactions',
    };
  }
  
  const campaigns = db.campaigns || {};
  for (const [campaignId, campaign] of Object.entries(campaigns)) {
    if (campaign.packages?.includes(packageName)) {
      const affectedVersions = campaign.affectedVersions?.[packageName];
      const cleanVersion = version.replace(/^[\^~]/, '');
      
      if (affectedVersions && !affectedVersions.includes(cleanVersion)) {
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
        severity: (campaign.severity as ScanIssue['severity']) || 'high',
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
 * Main scan function
 */
export function scan(content: string, filename: string): ScanResult {
  let directDeps: Record<string, string> = {};
  let lockPackages: Map<string, { version: string; isTransitive: boolean }> | null = null;
  let lockFileType: string | null = null;
  
  // Determine file type and parse
  if (filename.endsWith('.json') && !filename.includes('lock')) {
    // package.json
    directDeps = parsePackageJson(content);
  } else if (filename === 'pnpm-lock.yaml' || content.includes('lockfileVersion')) {
    if (content.includes('packages:') && !content.startsWith('{')) {
      // pnpm-lock.yaml
      lockPackages = parsePnpmLock(content);
      lockFileType = 'pnpm-lock.yaml';
    } else {
      // package-lock.json
      lockPackages = parseNpmLock(content);
      lockFileType = 'package-lock.json';
    }
  } else if (filename === 'yarn.lock' || content.includes('# yarn lockfile')) {
    lockPackages = parseYarnLock(content);
    lockFileType = 'yarn.lock';
  } else {
    // Try to auto-detect
    try {
      const parsed = JSON.parse(content);
      if (parsed.lockfileVersion || parsed.packages) {
        lockPackages = parseNpmLock(content);
        lockFileType = 'package-lock.json';
      } else {
        directDeps = parsePackageJson(content);
      }
    } catch {
      if (content.includes('packages:')) {
        lockPackages = parsePnpmLock(content);
        lockFileType = 'pnpm-lock.yaml';
      } else if (content.includes('version "')) {
        lockPackages = parseYarnLock(content);
        lockFileType = 'yarn.lock';
      } else {
        throw new Error('Unable to determine file type');
      }
    }
  }
  
  // Build package list to scan
  const packagesToScan = new Map<string, { version: string; isDirect: boolean; isTransitive: boolean }>();
  
  // Add direct dependencies
  for (const [name, version] of Object.entries(directDeps)) {
    packagesToScan.set(name, { version, isDirect: true, isTransitive: false });
  }
  
  // Add lock file packages
  if (lockPackages) {
    for (const [name, info] of lockPackages) {
      if (!packagesToScan.has(name)) {
        packagesToScan.set(name, { ...info, isDirect: false });
      }
    }
  }
  
  // Scan packages
  const results: ScanResult['results'] = {
    critical: [],
    high: [],
    medium: [],
    low: [],
  };
  
  for (const [name, info] of packagesToScan) {
    const issue = checkPackage(name, info.version, info.isDirect, info.isTransitive);
    if (issue) {
      results[issue.severity].push(issue);
    }
  }
  
  const directCount = Object.keys(directDeps).length || (lockPackages ? 0 : packagesToScan.size);
  const transitiveCount = lockPackages ? packagesToScan.size - directCount : 0;
  
  return {
    timestamp: new Date().toISOString(),
    scanMode: lockFileType ? 'deep' : 'direct',
    lockFile: lockFileType,
    packagesScanned: {
      total: packagesToScan.size,
      direct: directCount,
      transitive: transitiveCount,
    },
    totalIssues: results.critical.length + results.high.length + results.medium.length + results.low.length,
    transitiveIssues: [...results.critical, ...results.high, ...results.medium, ...results.low]
      .filter(i => i.isTransitive).length,
    results,
  };
}

