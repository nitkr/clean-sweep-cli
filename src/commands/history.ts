import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';

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

interface ScanReport {
  timestamp: string;
  scanPath: string;
  results: {
    threats: unknown[];
    safe: boolean;
    [key: string]: unknown;
  };
  suggestions?: string[];
  [key: string]: unknown;
}

export interface HistoryEntry {
  file: string;
  timestamp: string;
  scanPath: string;
  threatCount: number;
  safe: boolean;
}

export interface HistoryResult {
  total: number;
  scans: HistoryEntry[];
}

const DEFAULT_REPORTS_DIR = 'reports';

export function findReportFiles(reportsDir: string): string[] {
  if (!fs.existsSync(reportsDir)) {
    return [];
  }

  return fs.readdirSync(reportsDir)
    .filter(f => f.endsWith('.json'))
    .map(f => path.join(reportsDir, f))
    .sort();
}

export function parseReport(filePath: string): ScanReport | null {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const data = JSON.parse(content);

    if (!data || typeof data !== 'object') return null;
    if (typeof data.timestamp !== 'string') return null;
    if (!data.results || typeof data.results !== 'object') return null;
    if (!Array.isArray(data.results.threats)) return null;
    if (typeof data.results.safe !== 'boolean') return null;

    return data as ScanReport;
  } catch {
    return null;
  }
}

export function filterByDateRange(
  entries: HistoryEntry[],
  from?: string,
  to?: string
): HistoryEntry[] {
  let filtered = entries;

  if (from) {
    const fromDate = new Date(from);
    if (isNaN(fromDate.getTime())) {
      throw new Error(`Invalid 'from' date: ${from}`);
    }
    filtered = filtered.filter(e => new Date(e.timestamp) >= fromDate);
  }

  if (to) {
    const toDate = new Date(to);
    if (isNaN(toDate.getTime())) {
      throw new Error(`Invalid 'to' date: ${to}`);
    }
    filtered = filtered.filter(e => new Date(e.timestamp) <= toDate);
  }

  return filtered;
}

export function buildHistory(
  reportsDir: string,
  from?: string,
  to?: string
): HistoryResult {
  const files = findReportFiles(reportsDir);
  const entries: HistoryEntry[] = [];

  for (const file of files) {
    const report = parseReport(file);
    if (!report) continue;

    entries.push({
      file: path.basename(file),
      timestamp: report.timestamp,
      scanPath: report.scanPath,
      threatCount: report.results.threats.length,
      safe: report.results.safe,
    });
  }

  const filtered = filterByDateRange(entries, from, to);

  return {
    total: filtered.length,
    scans: filtered,
  };
}

function formatOutput(data: unknown, useJson: boolean): void {
  if (useJson) {
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(data);
  }
}

function printHistory(result: HistoryResult): void {
  console.log('Scan History');
  console.log('============');
  console.log(`Total scans: ${result.total}`);

  if (result.total === 0) {
    console.log('\nNo scan reports found.');
    return;
  }

  console.log('\n' + '-'.repeat(90));
  console.log(
    ' ' + 'Timestamp'.padEnd(26) +
    'Threats'.padStart(8) +
    'Status'.padStart(10) +
    '  ' + 'Scan Path'
  );
  console.log('-'.repeat(90));

  for (const scan of result.scans) {
    const ts = scan.timestamp.replace('T', ' ').replace(/\.\d+Z$/, 'Z');
    const status = scan.safe ? 'SAFE' : 'UNSAFE';
    console.log(
      ' ' + ts.padEnd(26) +
      String(scan.threatCount).padStart(8) +
      status.padStart(10) +
      '  ' + scan.scanPath
    );
  }

  console.log('-'.repeat(90));
}

export function registerHistoryCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  program
    .command('history')
    .description('View scan history from saved reports')
    .option('--reports-dir <dir>', 'Reports directory', DEFAULT_REPORTS_DIR)
    .option('--from <date>', 'Filter scans from this date (ISO 8601)')
    .option('--to <date>', 'Filter scans up to this date (ISO 8601)')
    .option('--json', 'Output results as JSON', false)
    .action((cmdOptions) => {
      const opts = getOpts();
      const useJson = opts.json || cmdOptions.json;
      const reportsDir = path.resolve(cmdOptions.reportsDir);

      try {
        const result = buildHistory(reportsDir, cmdOptions.from, cmdOptions.to);

        if (useJson) {
          formatOutput(result, true);
          return;
        }

        printHistory(result);
      } catch (err) {
        const error = { error: 'Failed to load scan history', message: String(err) };
        formatOutput(error, useJson);
        process.exit(1);
      }
    });
}
