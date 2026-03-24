import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import fg from 'fast-glob';
import { detectThreats, Threat } from '../malware-scanner';

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
  logLevel: string;
}

export interface TypeCount {
  type: string;
  count: number;
}

export interface SeverityCount {
  severity: string;
  count: number;
}

export interface CategoryCount {
  category: string;
  count: number;
}

export interface SummaryResult {
  path: string;
  totalFiles: number;
  totalThreats: number;
  riskScore: number;
  riskLevel: string;
  byType: TypeCount[];
  bySeverity: SeverityCount[];
  byCategory: CategoryCount[];
  affectedFiles: number;
}

const HIGH_SEVERITY_TYPES = new Set([
  'php_eval', 'php_shell_exec', 'php_system', 'php_passthru', 'php_exec',
  'php_proc_open', 'php_popen', 'php_pcntl_exec', 'php_assert',
  'php_preg_replace_eval', 'php_create_function', 'js_eval_dynamic',
  'js_child_process_exec', 'js_child_process_spawn',
]);

const MEDIUM_SEVERITY_TYPES = new Set([
  'php_base64_decode', 'php_gzinflate', 'php_gzuncompress', 'php_str_rot13',
  'php_call_user_func', 'php_curl_exec', 'php_proc_terminate',
  'php_apache_child_terminate', 'js_function_dynamic', 'js_settimeout_dynamic',
  'js_setinterval_dynamic', 'js_eval_template_literal', 'js_function_constructor',
  'js_settimeout_concat', 'js_setinterval_concat', 'js_process_require',
  'js_process_binding',
]);

export function classifySeverity(type: string): string {
  if (HIGH_SEVERITY_TYPES.has(type)) return 'high';
  if (MEDIUM_SEVERITY_TYPES.has(type)) return 'medium';
  return 'low';
}

export function classifyCategory(type: string): string {
  if (type.startsWith('php_')) return 'php-code';
  if (type.startsWith('js_')) return 'js-code';
  if (type === 'base64_large' || type === 'char_encoding' || type === 'hex_escape' ||
      type === 'url_encoding' || type === 'nested_encoding' || type === 'mixed_case_base64') {
    return 'encoded-content';
  }
  if (type === 'suspicious_php_extension' || type === 'suspicious_php_filename' ||
      type === 'alternative_php' || type === 'path_traversal') {
    return 'suspicious-file';
  }
  return 'other';
}

export function groupByType(threats: Threat[]): TypeCount[] {
  const counts = new Map<string, number>();
  for (const threat of threats) {
    counts.set(threat.type, (counts.get(threat.type) || 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => b.count - a.count);
}

export function groupBySeverity(threats: Threat[]): SeverityCount[] {
  const counts = new Map<string, number>();
  for (const threat of threats) {
    const severity = classifySeverity(threat.type);
    counts.set(severity, (counts.get(severity) || 0) + 1);
  }
  const order = ['high', 'medium', 'low'];
  return order
    .filter(sev => counts.has(sev))
    .map(sev => ({ severity: sev, count: counts.get(sev)! }));
}

export function groupByCategory(threats: Threat[]): CategoryCount[] {
  const counts = new Map<string, number>();
  for (const threat of threats) {
    const category = classifyCategory(threat.type);
    counts.set(category, (counts.get(category) || 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([category, count]) => ({ category, count }))
    .sort((a, b) => b.count - a.count);
}

export function calculateRiskScore(threats: Threat[]): number {
  if (threats.length === 0) return 0;
  let score = 0;
  for (const threat of threats) {
    const severity = classifySeverity(threat.type);
    if (severity === 'high') score += 10;
    else if (severity === 'medium') score += 5;
    else score += 1;
  }
  return Math.min(score, 100);
}

export function riskLevelFromScore(score: number): string {
  if (score >= 70) return 'critical';
  if (score >= 40) return 'high';
  if (score >= 15) return 'medium';
  if (score > 0) return 'low';
  return 'none';
}

async function scanDirectory(targetPath: string): Promise<Threat[]> {
  const ignore = ['**/node_modules/**', '**/vendor/**', '**/dist/**', '**/.git/**'];
  const files = await fg('**/*', {
    cwd: targetPath,
    absolute: true,
    onlyFiles: true,
    ignore,
  });

  const threats: Threat[] = [];
  const scanExtensions = ['.php', '.js'];

  for (const file of files) {
    const ext = path.extname(file).toLowerCase();
    if (!scanExtensions.includes(ext)) continue;

    try {
      const content = fs.readFileSync(file, 'utf-8');
      const fileThreats = detectThreats(file, content, false);
      threats.push(...fileThreats);
    } catch {
      continue;
    }
  }

  return threats;
}

export async function generateSummary(targetPath: string): Promise<SummaryResult> {
  const threats = await scanDirectory(targetPath);
  const riskScore = calculateRiskScore(threats);
  const uniqueFiles = new Set(threats.map(t => t.file));

  return {
    path: targetPath,
    totalFiles: threats.length > 0 ? uniqueFiles.size : 0,
    totalThreats: threats.length,
    riskScore,
    riskLevel: riskLevelFromScore(riskScore),
    byType: groupByType(threats),
    bySeverity: groupBySeverity(threats),
    byCategory: groupByCategory(threats),
    affectedFiles: uniqueFiles.size,
  };
}

function formatOutput(data: unknown, useJson: boolean): void {
  if (useJson) {
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(data);
  }
}

function printTable(header: string, rows: [string, number][]): void {
  console.log(`\n${header}:`);
  console.log('  ' + '-'.repeat(38));
  console.log('  ' + 'Name'.padEnd(30) + 'Count'.padStart(8));
  console.log('  ' + '-'.repeat(38));
  for (const [name, count] of rows) {
    console.log('  ' + name.padEnd(30) + String(count).padStart(8));
  }
  console.log('  ' + '-'.repeat(38));
  const total = rows.reduce((sum, [, c]) => sum + c, 0);
  console.log('  ' + 'TOTAL'.padEnd(30) + String(total).padStart(8));
}

export function registerSummaryCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  program
    .command('summary')
    .description('Show a summary of scan results with risk scoring')
    .option('--path <path>', 'Directory to scan')
    .option('--json', 'Output results as JSON', false)
    .action(async (cmdOptions) => {
      const opts = getOpts();
      const targetPath = path.resolve(cmdOptions.path || opts.path);
      const useJson = opts.json || cmdOptions.json;

      if (!fs.existsSync(targetPath)) {
        const error = { error: 'Path does not exist', path: targetPath };
        formatOutput(error, useJson);
        process.exit(1);
      }

      const stats = fs.statSync(targetPath);
      if (!stats.isDirectory()) {
        const error = { error: 'Path is not a directory', path: targetPath };
        formatOutput(error, useJson);
        process.exit(1);
      }

      try {
        const result = await generateSummary(targetPath);

        if (useJson) {
          formatOutput(result, true);
          return;
        }

        console.log('Scan Summary');
        console.log('============');
        console.log(`Path: ${result.path}`);
        console.log(`Total threats: ${result.totalThreats}`);
        console.log(`Affected files: ${result.affectedFiles}`);
        console.log(`Risk score: ${result.riskScore}/100`);
        console.log(`Risk level: ${result.riskLevel.toUpperCase()}`);

        printTable(
          'Threats by Type',
          result.byType.map(r => [r.type, r.count])
        );

        printTable(
          'Threats by Severity',
          result.bySeverity.map(r => [r.severity, r.count])
        );

        printTable(
          'Threats by Category',
          result.byCategory.map(r => [r.category, r.count])
        );
      } catch (err) {
        const error = { error: 'Summary generation failed', message: String(err) };
        formatOutput(error, useJson);
        process.exit(1);
      }
    });
}
