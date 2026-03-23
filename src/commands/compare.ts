import { Command } from 'commander';
import * as fs from 'fs';
import { Threat } from '../malware-scanner';
import { Vulnerability } from '../vulnerability-scanner';
import { IntegrityResult } from '../file-integrity';

interface ScanResultJson {
  path: string;
  files?: string[];
  directories?: string[];
  totalFiles?: number;
  totalDirectories?: number;
  threats: Threat[];
  safe: boolean;
  dryRun?: boolean;
  whitelisted?: number;
  vulnerabilities?: Vulnerability[];
  integrity?: IntegrityResult;
  unknownFiles?: { files: string[]; count: number };
  suggestions?: string[];
}

interface CliOptions {
  dryRun: boolean;
  force: boolean;
  json: boolean;
  path: string;
  verbose: boolean;
  checkVulnerabilities: boolean;
  checkIntegrity: boolean;
  findUnknown: boolean;
  report: boolean;
  htmlReport: boolean;
  logLevel: string;
}

interface ThreatDelta {
  type: string;
  before: number;
  after: number;
  change: number;
}

interface FileDelta {
  added: string[];
  removed: string[];
}

interface ComparisonResult {
  baseline: { path: string; threatCount: number; safe: boolean };
  current: { path: string; threatCount: number; safe: boolean };
  threats: {
    baseline: number;
    current: number;
    delta: number;
    newThreats: Threat[];
    resolvedThreats: Threat[];
    byType: ThreatDelta[];
  };
  files: {
    baseline: number;
    current: number;
    delta: number;
    newFiles: string[];
    removedFiles: string[];
  };
  status: {
    improved: boolean;
    degraded: boolean;
    unchanged: boolean;
  };
  vulnerabilities?: {
    baseline: number;
    current: number;
    delta: number;
    newVulnerabilities: Vulnerability[];
    resolvedVulnerabilities: Vulnerability[];
  };
  integrity?: {
    baselineModified: number;
    currentModified: number;
    delta: number;
    newModified: string[];
    resolvedModified: string[];
  };
}

function threatKey(t: Threat): string {
  return `${t.file}:${t.type}:${t.line ?? ''}`;
}

function vulnKey(v: Vulnerability): string {
  return `${v.component}:${v.version}:${v.cve}`;
}

export function compareScanResults(baseline: ScanResultJson, current: ScanResultJson): ComparisonResult {
  const baselineThreatMap = new Map<string, Threat>();
  const currentThreatMap = new Map<string, Threat>();

  for (const t of baseline.threats) {
    baselineThreatMap.set(threatKey(t), t);
  }
  for (const t of current.threats) {
    currentThreatMap.set(threatKey(t), t);
  }

  const newThreats: Threat[] = [];
  const resolvedThreats: Threat[] = [];

  for (const [key, t] of currentThreatMap) {
    if (!baselineThreatMap.has(key)) {
      newThreats.push(t);
    }
  }
  for (const [key, t] of baselineThreatMap) {
    if (!currentThreatMap.has(key)) {
      resolvedThreats.push(t);
    }
  }

  const allTypes = new Set<string>();
  for (const t of baseline.threats) allTypes.add(t.type);
  for (const t of current.threats) allTypes.add(t.type);

  const baselineTypeCounts = new Map<string, number>();
  const currentTypeCounts = new Map<string, number>();
  for (const t of baseline.threats) {
    baselineTypeCounts.set(t.type, (baselineTypeCounts.get(t.type) || 0) + 1);
  }
  for (const t of current.threats) {
    currentTypeCounts.set(t.type, (currentTypeCounts.get(t.type) || 0) + 1);
  }

  const byType: ThreatDelta[] = [];
  for (const type of allTypes) {
    const before = baselineTypeCounts.get(type) || 0;
    const after = currentTypeCounts.get(type) || 0;
    if (before !== after) {
      byType.push({ type, before, after, change: after - before });
    }
  }
  byType.sort((a, b) => Math.abs(b.change) - Math.abs(a.change));

  const baselineFileSet = new Set(baseline.files ?? []);
  const currentFileSet = new Set(current.files ?? []);
  const newFiles: string[] = [];
  const removedFiles: string[] = [];

  for (const f of currentFileSet) {
    if (!baselineFileSet.has(f)) newFiles.push(f);
  }
  for (const f of baselineFileSet) {
    if (!currentFileSet.has(f)) removedFiles.push(f);
  }
  newFiles.sort();
  removedFiles.sort();

  const threatDelta = current.threats.length - baseline.threats.length;
  const improved = threatDelta < 0;
  const degraded = threatDelta > 0;

  const result: ComparisonResult = {
    baseline: {
      path: baseline.path,
      threatCount: baseline.threats.length,
      safe: baseline.safe,
    },
    current: {
      path: current.path,
      threatCount: current.threats.length,
      safe: current.safe,
    },
    threats: {
      baseline: baseline.threats.length,
      current: current.threats.length,
      delta: threatDelta,
      newThreats,
      resolvedThreats,
      byType,
    },
    files: {
      baseline: baseline.files?.length ?? 0,
      current: current.files?.length ?? 0,
      delta: (current.files?.length ?? 0) - (baseline.files?.length ?? 0),
      newFiles,
      removedFiles,
    },
    status: {
      improved,
      degraded,
      unchanged: !improved && !degraded,
    },
  };

  if (baseline.vulnerabilities || current.vulnerabilities) {
    const baseVulns = baseline.vulnerabilities ?? [];
    const currVulns = current.vulnerabilities ?? [];
    const baseVulnMap = new Map<string, Vulnerability>();
    const currVulnMap = new Map<string, Vulnerability>();

    for (const v of baseVulns) baseVulnMap.set(vulnKey(v), v);
    for (const v of currVulns) currVulnMap.set(vulnKey(v), v);

    const newVulnerabilities: Vulnerability[] = [];
    const resolvedVulnerabilities: Vulnerability[] = [];

    for (const [key, v] of currVulnMap) {
      if (!baseVulnMap.has(key)) newVulnerabilities.push(v);
    }
    for (const [key, v] of baseVulnMap) {
      if (!currVulnMap.has(key)) resolvedVulnerabilities.push(v);
    }

    result.vulnerabilities = {
      baseline: baseVulns.length,
      current: currVulns.length,
      delta: currVulns.length - baseVulns.length,
      newVulnerabilities,
      resolvedVulnerabilities,
    };
  }

  if (baseline.integrity || current.integrity) {
    const baseModified = new Set(baseline.integrity?.modifiedFiles ?? []);
    const currModified = new Set(current.integrity?.modifiedFiles ?? []);

    const newModified: string[] = [];
    const resolvedModified: string[] = [];

    for (const f of currModified) {
      if (!baseModified.has(f)) newModified.push(f);
    }
    for (const f of baseModified) {
      if (!currModified.has(f)) resolvedModified.push(f);
    }
    newModified.sort();
    resolvedModified.sort();

    result.integrity = {
      baselineModified: baseline.integrity?.modified ?? 0,
      currentModified: current.integrity?.modified ?? 0,
      delta: (current.integrity?.modified ?? 0) - (baseline.integrity?.modified ?? 0),
      newModified,
      resolvedModified,
    };
  }

  return result;
}

export function loadScanResult(filePath: string): ScanResultJson {
  const resolved = require('path').resolve(filePath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`File not found: ${resolved}`);
  }
  const content = fs.readFileSync(resolved, 'utf-8');
  const data = JSON.parse(content);

  if (!data || typeof data !== 'object') {
    throw new Error(`Invalid scan result: ${filePath}`);
  }
  if (!Array.isArray(data.threats)) {
    throw new Error(`Invalid scan result: missing 'threats' array in ${filePath}`);
  }
  if (typeof data.safe !== 'boolean') {
    throw new Error(`Invalid scan result: missing 'safe' boolean in ${filePath}`);
  }

  return data as ScanResultJson;
}

function formatOutput(data: unknown, useJson: boolean): void {
  if (useJson) {
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(data);
  }
}

function printComparison(result: ComparisonResult): void {
  console.log('Scan Comparison Report');
  console.log('======================');
  console.log(`Baseline: ${result.baseline.path} (${result.baseline.threatCount} threats, ${result.baseline.safe ? 'SAFE' : 'UNSAFE'})`);
  console.log(`Current:  ${result.current.path} (${result.current.threatCount} threats, ${result.current.safe ? 'SAFE' : 'UNSAFE'})`);

  if (result.status.improved) {
    console.log(`\nStatus: IMPROVED (${Math.abs(result.threats.delta)} threat(s) resolved)`);
  } else if (result.status.degraded) {
    console.log(`\nStatus: DEGRADED (${result.threats.delta} new threat(s) found)`);
  } else {
    console.log('\nStatus: UNCHANGED');
  }

  console.log('\nThreats:');
  console.log(`  Baseline: ${result.threats.baseline}`);
  console.log(`  Current:  ${result.threats.current}`);
  console.log(`  Delta:    ${result.threats.delta >= 0 ? '+' : ''}${result.threats.delta}`);

  if (result.threats.newThreats.length > 0) {
    console.log(`\n  New threats (${result.threats.newThreats.length}):`);
    for (const t of result.threats.newThreats) {
      const lineInfo = t.line !== null ? `:${t.line}` : '';
      console.log(`    + ${t.file}${lineInfo} [${t.type}]`);
    }
  }

  if (result.threats.resolvedThreats.length > 0) {
    console.log(`\n  Resolved threats (${result.threats.resolvedThreats.length}):`);
    for (const t of result.threats.resolvedThreats) {
      const lineInfo = t.line !== null ? `:${t.line}` : '';
      console.log(`    - ${t.file}${lineInfo} [${t.type}]`);
    }
  }

  if (result.threats.byType.length > 0) {
    console.log('\n  Changes by type:');
    for (const d of result.threats.byType) {
      const sign = d.change >= 0 ? '+' : '';
      console.log(`    ${d.type}: ${d.before} -> ${d.after} (${sign}${d.change})`);
    }
  }

  console.log('\nFiles:');
  console.log(`  Baseline: ${result.files.baseline}`);
  console.log(`  Current:  ${result.files.current}`);
  console.log(`  Delta:    ${result.files.delta >= 0 ? '+' : ''}${result.files.delta}`);

  if (result.vulnerabilities) {
    console.log('\nVulnerabilities:');
    console.log(`  Baseline: ${result.vulnerabilities.baseline}`);
    console.log(`  Current:  ${result.vulnerabilities.current}`);
    console.log(`  Delta:    ${result.vulnerabilities.delta >= 0 ? '+' : ''}${result.vulnerabilities.delta}`);

    if (result.vulnerabilities.newVulnerabilities.length > 0) {
      console.log(`\n  New vulnerabilities (${result.vulnerabilities.newVulnerabilities.length}):`);
      for (const v of result.vulnerabilities.newVulnerabilities) {
        console.log(`    + [${v.severity}] ${v.component} ${v.version}: ${v.title} (${v.cve})`);
      }
    }

    if (result.vulnerabilities.resolvedVulnerabilities.length > 0) {
      console.log(`\n  Resolved vulnerabilities (${result.vulnerabilities.resolvedVulnerabilities.length}):`);
      for (const v of result.vulnerabilities.resolvedVulnerabilities) {
        console.log(`    - [${v.severity}] ${v.component} ${v.version}: ${v.title} (${v.cve})`);
      }
    }
  }

  if (result.integrity) {
    console.log('\nCore Integrity:');
    console.log(`  Baseline modified: ${result.integrity.baselineModified}`);
    console.log(`  Current modified:  ${result.integrity.currentModified}`);
    console.log(`  Delta:             ${result.integrity.delta >= 0 ? '+' : ''}${result.integrity.delta}`);

    if (result.integrity.newModified.length > 0) {
      console.log(`\n  Newly modified files (${result.integrity.newModified.length}):`);
      for (const f of result.integrity.newModified) {
        console.log(`    + ${f}`);
      }
    }

    if (result.integrity.resolvedModified.length > 0) {
      console.log(`\n  Restored files (${result.integrity.resolvedModified.length}):`);
      for (const f of result.integrity.resolvedModified) {
        console.log(`    - ${f}`);
      }
    }
  }
}

export function registerCompareCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  program
    .command('compare <baseline> <current>')
    .description('Compare two JSON scan results')
    .option('--json', 'Output results as JSON', false)
    .action(async (baselinePath: string, currentPath: string, cmdOptions: { json: boolean }) => {
      const opts = getOpts();
      const useJson = opts.json || cmdOptions.json;

      try {
        const baseline = loadScanResult(baselinePath);
        const current = loadScanResult(currentPath);
        const result = compareScanResults(baseline, current);

        if (useJson) {
          formatOutput(result, true);
          return;
        }

        printComparison(result);
      } catch (err) {
        const error = { error: 'Comparison failed', message: String(err) };
        formatOutput(error, useJson);
        process.exit(1);
      }
    });
}
