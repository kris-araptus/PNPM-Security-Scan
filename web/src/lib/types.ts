export interface ScanIssue {
  package: string;
  version: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  type: string;
  reason: string;
  action: string;
  isDirect: boolean;
  isTransitive: boolean;
  dependencyChain: string[];
  campaign?: string;
  affectedVersions?: string[];
}

export interface ScanResult {
  timestamp: string;
  scanMode: 'direct' | 'deep';
  lockFile: string | null;
  packagesScanned: {
    total: number;
    direct: number;
    transitive: number;
  };
  totalIssues: number;
  transitiveIssues: number;
  results: {
    critical: ScanIssue[];
    high: ScanIssue[];
    medium: ScanIssue[];
    low: ScanIssue[];
  };
}

export interface ThreatDatabase {
  version: string;
  lastUpdated: string;
  campaigns: Record<string, Campaign>;
  knownMalicious: {
    confirmed: string[];
    typosquatting: string[];
    credentialTheft: string[];
    cryptoMalware: string[];
  };
  trustedPackages: {
    packages: string[];
  };
}

export interface Campaign {
  name: string;
  date: string;
  severity: string;
  description: string;
  packages: string[];
  affectedVersions?: Record<string, string[]>;
}

