import { useState, useCallback, useRef } from 'react';
import type { ScanResult, ScanIssue } from '../lib/types';

type ScanState = 'idle' | 'uploading' | 'scanning' | 'complete' | 'error';

export default function Scanner() {
  const [state, setState] = useState<ScanState>('idle');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const textAreaRef = useRef<HTMLTextAreaElement>(null);

  const handleScan = useCallback(async (content: string, name: string) => {
    setState('scanning');
    setError(null);
    setFileName(name);

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content, filename: name }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Scan failed');
      }

      const data = await response.json();
      setResult(data);
      setState('complete');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
      setState('error');
    }
  }, []);

  const handleFileDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);

    const file = e.dataTransfer.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        const content = event.target?.result as string;
        handleScan(content, file.name);
      };
      reader.readAsText(file);
    }
  }, [handleScan]);

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        const content = event.target?.result as string;
        handleScan(content, file.name);
      };
      reader.readAsText(file);
    }
  }, [handleScan]);

  const handlePaste = useCallback(() => {
    const content = textAreaRef.current?.value;
    if (content?.trim()) {
      // Try to detect file type from content
      let filename = 'package.json';
      if (content.includes('lockfileVersion')) {
        filename = content.includes('packages:') ? 'pnpm-lock.yaml' : 'package-lock.json';
      } else if (content.includes('# yarn lockfile')) {
        filename = 'yarn.lock';
      }
      handleScan(content, filename);
    }
  }, [handleScan]);

  const handleReset = useCallback(() => {
    setState('idle');
    setResult(null);
    setError(null);
    setFileName(null);
    if (textAreaRef.current) textAreaRef.current.value = '';
    if (fileInputRef.current) fileInputRef.current.value = '';
  }, []);

  return (
    <div className="w-full">
      {state === 'idle' && (
        <div className="space-y-6">
          {/* Drop Zone */}
          <div
            className={`drop-zone p-8 sm:p-12 text-center cursor-pointer transition-all ${
              isDragging ? 'dragging' : ''
            }`}
            onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={handleFileDrop}
            onClick={() => fileInputRef.current?.click()}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".json,.yaml,.yml,.lock"
              onChange={handleFileSelect}
              className="hidden"
            />
            
            <div className="flex flex-col items-center gap-4">
              <div className={`w-16 h-16 rounded-full flex items-center justify-center transition-colors ${
                isDragging ? 'bg-araptus/20' : 'bg-slate-mid/50'
              }`}>
                <svg className={`w-8 h-8 transition-colors ${isDragging ? 'text-araptus-glow' : 'text-text-secondary'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                </svg>
              </div>
              
              <div>
                <p className="text-lg text-text-primary font-medium">
                  Drop your file here
                </p>
                <p className="text-text-secondary mt-1">
                  or click to browse
                </p>
              </div>
              
              <div className="flex flex-wrap justify-center gap-2 mt-2">
                {['package.json', 'pnpm-lock.yaml', 'package-lock.json', 'yarn.lock'].map((file) => (
                  <span key={file} className="px-3 py-1 rounded-full bg-slate-mid/50 text-text-muted text-sm font-mono">
                    {file}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Or Divider */}
          <div className="flex items-center gap-4">
            <div className="flex-1 h-px bg-slate-mid"></div>
            <span className="text-text-muted text-sm">or paste content</span>
            <div className="flex-1 h-px bg-slate-mid"></div>
          </div>

          {/* Paste Area */}
          <div className="space-y-4">
            <textarea
              ref={textAreaRef}
              placeholder='Paste your package.json or lock file content here...'
              className="input-field w-full h-48 resize-none text-sm"
              spellCheck={false}
            />
            <button
              onClick={handlePaste}
              className="btn-primary w-full sm:w-auto"
            >
              Scan Dependencies
            </button>
          </div>
        </div>
      )}

      {state === 'scanning' && (
        <div className="card p-8 text-center">
          <div className="flex flex-col items-center gap-6">
            <div className="relative">
              <div className="w-20 h-20 rounded-full border-4 border-slate-mid border-t-araptus animate-spin"></div>
              <div className="absolute inset-0 flex items-center justify-center">
                <svg className="w-8 h-8 text-araptus-glow animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
            </div>
            <div>
              <p className="text-xl font-semibold text-text-primary">Scanning Dependencies</p>
              <p className="text-text-secondary mt-1">
                Analyzing <span className="text-araptus-glow font-mono">{fileName}</span>
              </p>
            </div>
          </div>
        </div>
      )}

      {state === 'error' && (
        <div className="card p-8 border-alert/30">
          <div className="flex flex-col items-center gap-4 text-center">
            <div className="w-16 h-16 rounded-full bg-alert/10 flex items-center justify-center">
              <svg className="w-8 h-8 text-alert" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
            <div>
              <p className="text-xl font-semibold text-alert">Scan Failed</p>
              <p className="text-text-secondary mt-2">{error}</p>
            </div>
            <button onClick={handleReset} className="btn-primary mt-4">
              Try Again
            </button>
          </div>
        </div>
      )}

      {state === 'complete' && result && (
        <ScanResults result={result} onReset={handleReset} fileName={fileName} />
      )}
    </div>
  );
}

function ScanResults({ result, onReset, fileName }: { result: ScanResult; onReset: () => void; fileName: string | null }) {
  const hasIssues = result.totalIssues > 0;
  const allIssues = [
    ...result.results.critical,
    ...result.results.high,
    ...result.results.medium,
    ...result.results.low,
  ];

  return (
    <div className="space-y-6">
      {/* Summary Card */}
      <div className={`card p-6 ${hasIssues ? 'border-alert/30' : 'border-safe/30'}`}>
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className={`w-14 h-14 rounded-xl flex items-center justify-center ${
              hasIssues ? 'bg-alert/10' : 'bg-safe/10'
            }`}>
              {hasIssues ? (
                <svg className="w-7 h-7 text-alert" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              ) : (
                <svg className="w-7 h-7 text-safe" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              )}
            </div>
            <div>
              <h2 className={`text-2xl font-bold ${hasIssues ? 'text-alert' : 'text-safe'}`}>
                {hasIssues ? `${result.totalIssues} Issue${result.totalIssues > 1 ? 's' : ''} Found` : 'All Clear!'}
              </h2>
              <p className="text-text-secondary">
                Scanned {result.packagesScanned.total} packages
                {result.scanMode === 'deep' && (
                  <span className="text-info"> • Deep scan via {result.lockFile}</span>
                )}
              </p>
            </div>
          </div>
          
          <button onClick={onReset} className="text-text-secondary hover:text-text-primary transition-colors flex items-center gap-2">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            Scan Another
          </button>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-6">
          <StatCard label="Total" value={result.packagesScanned.total} />
          <StatCard label="Direct" value={result.packagesScanned.direct} />
          <StatCard label="Transitive" value={result.packagesScanned.transitive} color="info" />
          <StatCard label="Issues" value={result.totalIssues} color={hasIssues ? 'alert' : 'safe'} />
        </div>
      </div>

      {/* Severity Breakdown */}
      {hasIssues && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <SeverityCard severity="critical" count={result.results.critical.length} />
          <SeverityCard severity="high" count={result.results.high.length} />
          <SeverityCard severity="medium" count={result.results.medium.length} />
          <SeverityCard severity="low" count={result.results.low.length} />
        </div>
      )}

      {/* Quick Action Box */}
      {hasIssues && (
        <div className="card p-5 border-alert/30 bg-gradient-to-r from-alert/5 to-transparent">
          <h3 className="font-semibold text-alert text-sm mb-3 flex items-center gap-2">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
            Immediate Action Required
          </h3>
          <div className="grid sm:grid-cols-2 gap-4 text-sm">
            <div>
              <p className="text-text-primary font-medium mb-1">To fix in your GitHub repo:</p>
              <ol className="text-text-secondary space-y-1 list-decimal list-inside text-xs">
                <li>Open your repo's <code className="text-araptus-glow">package.json</code></li>
                <li>Remove the flagged package(s) below</li>
                <li>Run <code className="text-safe">npm install</code> or <code className="text-safe">pnpm install</code></li>
                <li>Commit and push your changes</li>
              </ol>
            </div>
            <div>
              <p className="text-text-primary font-medium mb-1">Command to remove:</p>
              <div className="bg-void/50 rounded-lg p-2 font-mono text-xs overflow-x-auto">
                <span className="text-text-muted">$</span>{' '}
                <span className="text-araptus-glow">npm uninstall {allIssues.slice(0, 3).map(i => i.package).join(' ')}</span>
                {allIssues.length > 3 && <span className="text-text-muted"> ...</span>}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Issues List */}
      {hasIssues && (
        <div className="space-y-4">
          <h3 className="text-lg font-semibold text-text-primary">Detected Threats</h3>
          <div className="space-y-3">
            {allIssues.map((issue, index) => (
              <IssueCard key={`${issue.package}-${index}`} issue={issue} />
            ))}
          </div>
        </div>
      )}

      {/* Safe Message */}
      {!hasIssues && (
        <div className="card p-8 text-center border-safe/20">
          <div className="flex flex-col items-center gap-4">
            <div className="text-6xl">🛡️</div>
            <div>
              <p className="text-xl font-semibold text-safe">Your dependencies look secure!</p>
              <p className="text-text-secondary mt-2">
                No known malicious packages were detected in your project.
              </p>
            </div>
            <div className="mt-4 p-4 rounded-lg bg-slate-mid/30 text-left max-w-md">
              <p className="text-sm text-text-secondary">
                <strong className="text-text-primary">Pro tip:</strong> Run this scan regularly and integrate it into your CI/CD pipeline for continuous protection.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, color = 'default' }: { label: string; value: number; color?: string }) {
  const colorClasses = {
    default: 'text-text-primary',
    info: 'text-info',
    safe: 'text-safe',
    alert: 'text-alert',
  };

  return (
    <div className="p-4 rounded-lg bg-slate-mid/30">
      <p className="text-text-muted text-sm">{label}</p>
      <p className={`text-2xl font-bold font-mono ${colorClasses[color as keyof typeof colorClasses] || colorClasses.default}`}>
        {value}
      </p>
    </div>
  );
}

function SeverityCard({ severity, count }: { severity: string; count: number }) {
  const config = {
    critical: { label: 'Critical', color: 'alert', icon: '🚨' },
    high: { label: 'High', color: 'warning', icon: '⚠️' },
    medium: { label: 'Medium', color: 'info', icon: '⚡' },
    low: { label: 'Low', color: 'text-muted', icon: 'ℹ️' },
  };

  const cfg = config[severity as keyof typeof config];

  return (
    <div className={`card p-4 ${count > 0 ? `border-${cfg.color}/30` : ''}`}>
      <div className="flex items-center gap-3">
        <span className="text-2xl">{cfg.icon}</span>
        <div>
          <p className="text-text-muted text-sm">{cfg.label}</p>
          <p className={`text-xl font-bold font-mono ${count > 0 ? `text-${cfg.color}` : 'text-text-muted'}`}>
            {count}
          </p>
        </div>
      </div>
    </div>
  );
}

function IssueCard({ issue }: { issue: ScanIssue }) {
  const severityConfig = {
    critical: { badge: 'badge-critical', glow: 'border-alert/30' },
    high: { badge: 'badge-high', glow: 'border-warning/30' },
    medium: { badge: 'badge-medium', glow: 'border-info/30' },
    low: { badge: 'badge-safe', glow: 'border-slate-mid' },
  };

  const cfg = severityConfig[issue.severity as keyof typeof severityConfig] || severityConfig.low;

  return (
    <div className={`card p-4 ${cfg.glow}`}>
      <div className="flex flex-col sm:flex-row sm:items-start gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <span className={`px-2 py-0.5 rounded text-xs font-medium uppercase ${cfg.badge}`}>
              {issue.severity}
            </span>
            {issue.isTransitive && (
              <span className="px-2 py-0.5 rounded text-xs font-medium bg-info/15 text-info border border-info/30">
                Transitive
              </span>
            )}
            <span className="px-2 py-0.5 rounded text-xs bg-slate-mid/50 text-text-muted">
              {issue.type}
            </span>
          </div>
          
          <h4 className="font-mono text-lg text-text-primary">
            {issue.package}
            <span className="text-text-muted">@{issue.version}</span>
          </h4>
          
          <p className="text-text-secondary mt-1 text-sm">{issue.reason}</p>
          
          {issue.dependencyChain && issue.dependencyChain.length > 0 && (
            <div className="mt-3 p-2 rounded bg-void/50 font-mono text-xs">
              <span className="text-text-muted">Chain: </span>
              <span className="text-info">
                {[...issue.dependencyChain, issue.package].join(' → ')}
              </span>
            </div>
          )}
        </div>
        
        <div className="sm:text-right">
          <p className="text-xs text-text-muted uppercase tracking-wide">Action</p>
          <p className="text-sm font-medium text-alert mt-1">{issue.action}</p>
        </div>
      </div>
    </div>
  );
}

