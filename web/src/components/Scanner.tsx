import { useState, useCallback, useRef, useEffect } from 'react';
import type { ScanResult, ScanIssue } from '../lib/types';

type ScanState = 'idle' | 'uploading' | 'scanning' | 'complete' | 'error';
type ScanStage = 'parsing' | 'analyzing' | 'checking' | 'finalizing';

const SCANNER_VERSION = '2.0.0';

export default function Scanner() {
  const [state, setState] = useState<ScanState>('idle');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const [scanStage, setScanStage] = useState<ScanStage>('parsing');
  const [packagesFound, setPackagesFound] = useState(0);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const textAreaRef = useRef<HTMLTextAreaElement>(null);

  // Animate through scan stages
  useEffect(() => {
    if (state !== 'scanning') return;
    
    const stages: ScanStage[] = ['parsing', 'analyzing', 'checking', 'finalizing'];
    let idx = 0;
    
    const interval = setInterval(() => {
      idx = (idx + 1) % stages.length;
      setScanStage(stages[idx]);
      setPackagesFound(prev => prev + Math.floor(Math.random() * 15) + 5);
    }, 400);
    
    return () => clearInterval(interval);
  }, [state]);

  const handleScan = useCallback(async (content: string, name: string) => {
    setState('scanning');
    setError(null);
    setFileName(name);
    setScanStage('parsing');
    setPackagesFound(0);

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
      {/* Version Badge */}
      <div className="flex justify-end mb-4">
        <span className="px-3 py-1 rounded-full bg-araptus/10 text-araptus-glow text-xs font-mono border border-araptus/20">
          v{SCANNER_VERSION} • Deep Scan Enabled
        </span>
      </div>

      {state === 'idle' && (
        <div className="space-y-6">
          {/* Drop Zone with enhanced styling */}
          <div
            className={`drop-zone p-8 sm:p-12 text-center cursor-pointer transition-all relative overflow-hidden ${
              isDragging ? 'dragging' : ''
            }`}
            onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={handleFileDrop}
            onClick={() => fileInputRef.current?.click()}
          >
            {/* Animated background grid */}
            <div className="absolute inset-0 opacity-5">
              <div className="absolute inset-0" style={{
                backgroundImage: 'linear-gradient(rgba(87, 13, 248, 0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(87, 13, 248, 0.3) 1px, transparent 1px)',
                backgroundSize: '30px 30px'
              }} />
            </div>
            
            <input
              ref={fileInputRef}
              type="file"
              accept=".json,.yaml,.yml,.lock"
              onChange={handleFileSelect}
              className="hidden"
            />
            
            <div className="flex flex-col items-center gap-4 relative z-10">
              <div className={`w-20 h-20 rounded-2xl flex items-center justify-center transition-all duration-300 ${
                isDragging 
                  ? 'bg-araptus/20 scale-110 rotate-3' 
                  : 'bg-gradient-to-br from-slate-mid/50 to-obsidian'
              }`}>
                <svg className={`w-10 h-10 transition-all duration-300 ${isDragging ? 'text-araptus-glow scale-110' : 'text-text-secondary'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                </svg>
              </div>
              
              <div>
                <p className="text-xl text-text-primary font-semibold">
                  {isDragging ? 'Release to scan!' : 'Drop your file here'}
                </p>
                <p className="text-text-secondary mt-1">
                  or click to browse • supports lock files for deep scanning
                </p>
              </div>
              
              <div className="flex flex-wrap justify-center gap-2 mt-3">
                {[
                  { name: 'package.json', type: 'direct', color: 'text-warning' },
                  { name: 'pnpm-lock.yaml', type: 'deep', color: 'text-safe' },
                  { name: 'package-lock.json', type: 'deep', color: 'text-safe' },
                  { name: 'yarn.lock', type: 'deep', color: 'text-safe' },
                ].map((file) => (
                  <span key={file.name} className="px-3 py-1.5 rounded-lg bg-slate-mid/30 border border-slate-dark text-sm font-mono flex items-center gap-2">
                    <span className={file.color}>{file.name}</span>
                    {file.type === 'deep' && (
                      <span className="px-1.5 py-0.5 rounded text-[10px] bg-info/20 text-info border border-info/30">DEEP</span>
                    )}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Divider */}
          <div className="flex items-center gap-4">
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-slate-mid to-transparent"></div>
            <span className="text-text-muted text-sm px-4">or paste content</span>
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-slate-mid to-transparent"></div>
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
              className="btn-primary w-full sm:w-auto flex items-center justify-center gap-2"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              Scan Dependencies
            </button>
          </div>
        </div>
      )}

      {state === 'scanning' && (
        <div className="card p-8 text-center relative overflow-hidden">
          {/* Animated scanning lines */}
          <div className="absolute inset-0 overflow-hidden">
            <div className="scanning-lines" />
          </div>
          
          <div className="flex flex-col items-center gap-6 relative z-10">
            {/* Multi-ring spinner */}
            <div className="relative w-24 h-24">
              <div className="absolute inset-0 rounded-full border-4 border-slate-mid border-t-araptus animate-spin"></div>
              <div className="absolute inset-2 rounded-full border-4 border-slate-mid/50 border-b-araptus-light animate-spin" style={{ animationDirection: 'reverse', animationDuration: '1.5s' }}></div>
              <div className="absolute inset-4 rounded-full border-4 border-slate-mid/30 border-t-info animate-spin" style={{ animationDuration: '2s' }}></div>
              <div className="absolute inset-0 flex items-center justify-center">
                <svg className="w-8 h-8 text-araptus-glow" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
            </div>
            
            <div>
              <p className="text-2xl font-bold text-text-primary mb-2">Deep Scanning</p>
              <p className="text-text-secondary">
                Analyzing <span className="text-araptus-glow font-mono">{fileName}</span>
              </p>
            </div>
            
            {/* Scan Stages Progress */}
            <div className="w-full max-w-md">
              <div className="flex justify-between mb-2">
                {(['parsing', 'analyzing', 'checking', 'finalizing'] as ScanStage[]).map((stage, idx) => (
                  <div key={stage} className={`flex flex-col items-center transition-all duration-300 ${
                    scanStage === stage ? 'text-araptus-glow scale-110' : 'text-text-muted'
                  }`}>
                    <div className={`w-3 h-3 rounded-full transition-all ${
                      scanStage === stage 
                        ? 'bg-araptus glow-accent' 
                        : idx < (['parsing', 'analyzing', 'checking', 'finalizing'] as ScanStage[]).indexOf(scanStage)
                          ? 'bg-safe'
                          : 'bg-slate-mid'
                    }`} />
                    <span className="text-xs mt-1 capitalize">{stage}</span>
                  </div>
                ))}
              </div>
              <div className="progress-bar">
                <div 
                  className="progress-bar-fill transition-all duration-300"
                  style={{ width: `${((['parsing', 'analyzing', 'checking', 'finalizing'] as ScanStage[]).indexOf(scanStage) + 1) * 25}%` }}
                />
              </div>
            </div>
            
            {/* Live stats */}
            <div className="flex gap-6 text-sm">
              <div className="text-center">
                <p className="text-2xl font-mono font-bold text-info animate-pulse">{packagesFound}</p>
                <p className="text-text-muted">packages found</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-mono font-bold text-araptus-glow">137+</p>
                <p className="text-text-muted">threats checked</p>
              </div>
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
  const [copied, setCopied] = useState<string | null>(null);
  const hasIssues = result.totalIssues > 0;
  const allIssues = [
    ...result.results.critical,
    ...result.results.high,
    ...result.results.medium,
    ...result.results.low,
  ];

  const copyToClipboard = async (text: string, id: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  const getRemovalCommand = (pm: 'npm' | 'pnpm' | 'yarn') => {
    const packages = allIssues.map(i => i.package).join(' ');
    switch (pm) {
      case 'npm': return `npm uninstall ${packages}`;
      case 'pnpm': return `pnpm remove ${packages}`;
      case 'yarn': return `yarn remove ${packages}`;
    }
  };

  return (
    <div className="space-y-6">
      {/* Summary Card with animation */}
      <div className={`card p-6 relative overflow-hidden ${hasIssues ? 'border-alert/30' : 'border-safe/30'}`}>
        {/* Animated gradient background */}
        <div className={`absolute inset-0 opacity-10 ${hasIssues ? 'bg-gradient-to-br from-alert/20 to-transparent' : 'bg-gradient-to-br from-safe/20 to-transparent'}`} />
        
        <div className="relative z-10">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
              <div className={`w-16 h-16 rounded-2xl flex items-center justify-center ${
                hasIssues ? 'bg-alert/10 animate-pulse' : 'bg-safe/10'
            }`}>
              {hasIssues ? (
                  <svg className="w-8 h-8 text-alert" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              ) : (
                  <svg className="w-8 h-8 text-safe" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              )}
            </div>
            <div>
                <h2 className={`text-3xl font-bold ${hasIssues ? 'text-alert' : 'text-safe'}`}>
                {hasIssues ? `${result.totalIssues} Issue${result.totalIssues > 1 ? 's' : ''} Found` : 'All Clear!'}
              </h2>
                <p className="text-text-secondary flex flex-wrap items-center gap-2">
                Scanned {result.packagesScanned.total} packages
                {result.scanMode === 'deep' && (
                    <span className="px-2 py-0.5 rounded-full text-xs bg-info/15 text-info border border-info/30">
                      🔬 Deep Scan via {result.lockFile}
                    </span>
                )}
              </p>
            </div>
          </div>
          
            <button onClick={onReset} className="btn-secondary flex items-center gap-2">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            Scan Another
          </button>
        </div>

          {/* Stats Grid with visual enhancements */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-6">
            <StatCard label="Total" value={result.packagesScanned.total} icon="📦" />
            <StatCard label="Direct" value={result.packagesScanned.direct} icon="📍" />
            <StatCard label="Transitive" value={result.packagesScanned.transitive} icon="🔗" color="info" />
            <StatCard label="Issues" value={result.totalIssues} icon={hasIssues ? "⚠️" : "✅"} color={hasIssues ? 'alert' : 'safe'} />
          </div>
        </div>
      </div>

      {/* Severity Breakdown with enhanced visuals */}
      {hasIssues && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <SeverityCard severity="critical" count={result.results.critical.length} />
          <SeverityCard severity="high" count={result.results.high.length} />
          <SeverityCard severity="medium" count={result.results.medium.length} />
          <SeverityCard severity="low" count={result.results.low.length} />
        </div>
      )}

      {/* Quick Action Box with copy commands */}
      {hasIssues && (
        <div className="card p-5 border-alert/30 bg-gradient-to-r from-alert/5 to-transparent">
          <h3 className="font-semibold text-alert text-sm mb-4 flex items-center gap-2">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
            Quick Fix Commands
          </h3>
          
          <div className="grid sm:grid-cols-3 gap-3">
            {(['npm', 'pnpm', 'yarn'] as const).map((pm) => (
              <button
                key={pm}
                onClick={() => copyToClipboard(getRemovalCommand(pm), pm)}
                className={`p-3 rounded-lg bg-void/50 border transition-all text-left group hover:border-araptus/50 ${
                  copied === pm ? 'border-safe/50' : 'border-slate-dark'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold text-text-muted uppercase">{pm}</span>
                  {copied === pm ? (
                    <span className="text-safe text-xs">✓ Copied!</span>
                  ) : (
                    <svg className="w-4 h-4 text-text-muted opacity-0 group-hover:opacity-100 transition-opacity" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                    </svg>
                  )}
            </div>
                <code className="text-xs text-araptus-glow font-mono block truncate">
                  {getRemovalCommand(pm)}
                </code>
              </button>
            ))}
          </div>
          
          <p className="text-xs text-text-muted mt-4">
            💡 Click a command to copy, then paste in your terminal to remove the malicious packages.
          </p>
        </div>
      )}

      {/* Issues List with enhanced cards */}
      {hasIssues && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold text-text-primary">Detected Threats</h3>
            <span className="text-text-muted text-sm">
              {result.transitiveIssues > 0 && (
                <span className="text-info">{result.transitiveIssues} in transitive deps</span>
              )}
            </span>
          </div>
          <div className="space-y-3">
            {allIssues.map((issue, index) => (
              <IssueCard key={`${issue.package}-${index}`} issue={issue} />
            ))}
          </div>
        </div>
      )}

      {/* Safe Message with enhanced visuals */}
      {!hasIssues && (
        <div className="card p-10 text-center border-safe/20 relative overflow-hidden">
          {/* Celebratory background */}
          <div className="absolute inset-0 bg-gradient-to-br from-safe/5 via-transparent to-araptus/5" />
          
          <div className="relative z-10 flex flex-col items-center gap-6">
            <div className="text-7xl animate-bounce">🛡️</div>
            <div>
              <p className="text-2xl font-bold text-safe mb-2">Your dependencies look secure!</p>
              <p className="text-text-secondary max-w-md mx-auto">
                No known malicious packages were detected. Keep your dependencies updated and scan regularly!
              </p>
            </div>
            
            <div className="flex flex-wrap justify-center gap-4 mt-4">
              <div className="px-4 py-2 rounded-lg bg-slate-mid/30 text-sm">
                <span className="text-text-muted">Direct deps: </span>
                <span className="text-safe font-mono font-bold">{result.packagesScanned.direct}</span>
              </div>
              {result.packagesScanned.transitive > 0 && (
                <div className="px-4 py-2 rounded-lg bg-slate-mid/30 text-sm">
                  <span className="text-text-muted">Transitive: </span>
                  <span className="text-info font-mono font-bold">{result.packagesScanned.transitive}</span>
                </div>
              )}
            </div>
            
            <div className="mt-4 p-4 rounded-lg bg-slate-mid/20 text-left max-w-lg">
              <p className="text-sm text-text-secondary">
                <strong className="text-text-primary">🔒 Pro tip:</strong> Add this scan to your CI/CD pipeline for continuous protection. 
                <a href="https://github.com/kris-araptus/pnpm-security-scan#cicd-integration" target="_blank" rel="noopener" className="text-araptus-glow hover:underline ml-1">
                  See GitHub Actions example →
                </a>
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, icon, color = 'default' }: { label: string; value: number; icon: string; color?: string }) {
  const colorClasses = {
    default: 'text-text-primary',
    info: 'text-info',
    safe: 'text-safe',
    alert: 'text-alert',
  };

  return (
    <div className="p-4 rounded-xl bg-gradient-to-br from-slate-mid/30 to-obsidian border border-slate-dark/50">
      <div className="flex items-center gap-2 mb-1">
        <span className="text-lg">{icon}</span>
      <p className="text-text-muted text-sm">{label}</p>
      </div>
      <p className={`text-3xl font-bold font-mono ${colorClasses[color as keyof typeof colorClasses] || colorClasses.default}`}>
        {value.toLocaleString()}
      </p>
    </div>
  );
}

function SeverityCard({ severity, count }: { severity: string; count: number }) {
  const config = {
    critical: { label: 'Critical', color: 'alert', bgColor: 'bg-alert/10', borderColor: 'border-alert/30', icon: '🚨' },
    high: { label: 'High', color: 'warning', bgColor: 'bg-warning/10', borderColor: 'border-warning/30', icon: '⚠️' },
    medium: { label: 'Medium', color: 'info', bgColor: 'bg-info/10', borderColor: 'border-info/30', icon: '⚡' },
    low: { label: 'Low', color: 'text-muted', bgColor: 'bg-slate-mid/30', borderColor: 'border-slate-mid', icon: 'ℹ️' },
  };

  const cfg = config[severity as keyof typeof config];

  return (
    <div className={`card p-4 transition-all ${count > 0 ? cfg.borderColor : 'border-slate-dark/50'} ${count > 0 ? cfg.bgColor : ''}`}>
      <div className="flex items-center gap-3">
        <span className="text-2xl">{cfg.icon}</span>
        <div>
          <p className="text-text-muted text-sm">{cfg.label}</p>
          <p className={`text-2xl font-bold font-mono ${count > 0 ? `text-${cfg.color}` : 'text-text-muted'}`}>
            {count}
          </p>
        </div>
      </div>
    </div>
  );
}

function IssueCard({ issue }: { issue: ScanIssue }) {
  const [expanded, setExpanded] = useState(false);
  
  const severityConfig = {
    critical: { badge: 'badge-critical', glow: 'border-alert/40 hover:border-alert/60', bg: 'from-alert/5' },
    high: { badge: 'badge-high', glow: 'border-warning/40 hover:border-warning/60', bg: 'from-warning/5' },
    medium: { badge: 'badge-medium', glow: 'border-info/40 hover:border-info/60', bg: 'from-info/5' },
    low: { badge: 'badge-safe', glow: 'border-slate-mid hover:border-slate-light', bg: 'from-slate-mid/5' },
  };

  const cfg = severityConfig[issue.severity as keyof typeof severityConfig] || severityConfig.low;

  return (
    <div 
      className={`card p-5 cursor-pointer transition-all bg-gradient-to-r ${cfg.bg} to-transparent ${cfg.glow}`}
      onClick={() => setExpanded(!expanded)}
    >
      <div className="flex flex-col sm:flex-row sm:items-start gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <span className={`px-2.5 py-1 rounded-lg text-xs font-semibold uppercase ${cfg.badge}`}>
              {issue.severity}
            </span>
            {issue.isTransitive && (
              <span className="px-2 py-1 rounded-lg text-xs font-medium bg-info/15 text-info border border-info/30 flex items-center gap-1">
                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                </svg>
                Transitive
              </span>
            )}
            <span className="px-2 py-1 rounded-lg text-xs bg-slate-mid/50 text-text-muted">
              {issue.type}
            </span>
          </div>
          
          <h4 className="font-mono text-lg text-text-primary flex items-center gap-2">
            <span className="text-araptus-glow">{issue.package}</span>
            <span className="text-text-muted text-base">@{issue.version}</span>
          </h4>
          
          <p className="text-text-secondary mt-2 text-sm leading-relaxed">{issue.reason}</p>
          
          {/* Expanded details */}
          {expanded && (
            <div className="mt-4 space-y-3 animate-fadeIn">
              {issue.affectedVersions && issue.affectedVersions.length > 0 && (
                <div className="p-3 rounded-lg bg-void/50 border border-slate-dark">
                  <p className="text-xs text-text-muted mb-1">Affected Versions:</p>
                  <div className="flex flex-wrap gap-1">
                    {issue.affectedVersions.map(v => (
                      <span key={v} className="px-2 py-0.5 rounded text-xs font-mono bg-alert/10 text-alert border border-alert/20">
                        {v}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              
              {issue.campaign && (
                <div className="p-3 rounded-lg bg-void/50 border border-slate-dark">
                  <p className="text-xs text-text-muted mb-1">Part of Campaign:</p>
                  <span className="text-warning font-medium">{issue.campaign}</span>
                </div>
              )}
            </div>
          )}
          
          {/* Dependency Chain */}
          {issue.dependencyChain && issue.dependencyChain.length > 0 && (
            <div className="mt-3 p-3 rounded-lg bg-void/50 border border-slate-dark font-mono text-xs overflow-x-auto">
              <span className="text-text-muted">Chain: </span>
              <span className="text-info whitespace-nowrap">
                {[...issue.dependencyChain, issue.package].map((pkg, idx, arr) => (
                  <span key={pkg}>
                    {pkg}
                    {idx < arr.length - 1 && <span className="text-text-muted mx-2">→</span>}
                  </span>
                ))}
              </span>
            </div>
          )}
        </div>
        
        <div className="sm:text-right flex-shrink-0">
          <p className="text-xs text-text-muted uppercase tracking-wide mb-1">Action</p>
          <p className="text-sm font-semibold text-alert leading-snug">{issue.action}</p>
          <button className="mt-2 text-xs text-text-muted hover:text-text-primary transition-colors">
            {expanded ? '▲ Less' : '▼ More'}
          </button>
        </div>
      </div>
    </div>
  );
}
