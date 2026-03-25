import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';

interface CliOptions {
  dryRun: boolean;
  force: boolean;
  json: boolean;
  path: string;
  verbose: boolean;
}

export interface CronJob {
  id: number;
  expression: string;
  command: string;
  enabled: boolean;
  rawLine: string;
  lineNumber: number;
}

export interface CronGuardIssue {
  type: 'missing' | 'disabled' | 'invalid_expression' | 'path_not_found' | 'modified' | 'suspicious' | 'excessive_frequency';
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  jobId?: number;
  message: string;
  details?: string;
}

export interface FrequencyAnalysis {
  expression: string;
  runsPerDay: number;
  intervalMinutes: number | null;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NORMAL';
  description: string;
}

export interface CronGuardResult {
  success: boolean;
  healthy: boolean;
  jobsChecked: number;
  jobs: CronJob[];
  issues: CronGuardIssue[];
  message?: string;
}

const CLEAN_SWEEP_MARKER = 'clean-sweep';

const SUSPICIOUS_PATTERNS = [
  { pattern: /base64/i, severity: 'HIGH' as const, description: 'Base64 encoded command detected' },
  { pattern: /eval\s*\(/i, severity: 'HIGH' as const, description: 'PHP eval() pattern detected' },
  { pattern: /wget\s+http/i, severity: 'HIGH' as const, description: 'wget from external URL detected' },
  { pattern: /curl\s+http/i, severity: 'HIGH' as const, description: 'curl from external URL detected' },
  { pattern: /(\/dev\/null\s*2>&1|2>&1\s*>\s*\/dev\/null)/i, severity: 'MEDIUM' as const, description: 'Output suppression detected' },
  { pattern: /chmod\s+777/i, severity: 'MEDIUM' as const, description: 'Overly permissive chmod 777 detected' },
  { pattern: /passthru|shell_exec|system\s*\(/i, severity: 'MEDIUM' as const, description: 'Shell execution function detected' },
];

export function isCleanSweepLine(line: string): boolean {
  return line.includes(CLEAN_SWEEP_MARKER) && !line.trimStart().startsWith('#');
}

export function isDisabledCleanSweepLine(line: string): boolean {
  const trimmed = line.trimStart();
  return trimmed.startsWith('# ') && trimmed.includes(CLEAN_SWEEP_MARKER);
}

export function parseCrontab(crontab: string): CronJob[] {
  const lines = crontab.split('\n');
  const jobs: CronJob[] = [];
  let id = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    if (trimmed === '' || (trimmed.startsWith('#') && !isDisabledCleanSweepLine(trimmed))) {
      continue;
    }

    if (isCleanSweepLine(trimmed)) {
      const parts = trimmed.split(/\s+/);
      const expression = parts.slice(0, 5).join(' ');
      const command = parts.slice(5).join(' ');
      jobs.push({ id: id++, expression, command, enabled: true, rawLine: trimmed, lineNumber: i + 1 });
    } else if (isDisabledCleanSweepLine(trimmed)) {
      const uncommented = trimmed.replace(/^#\s*/, '');
      const parts = uncommented.split(/\s+/);
      const expression = parts.slice(0, 5).join(' ');
      const command = parts.slice(5).join(' ');
      jobs.push({ id: id++, expression, command, enabled: false, rawLine: trimmed, lineNumber: i + 1 });
    }
  }

  return jobs;
}

export function isValidCronExpression(expression: string): boolean {
  const parts = expression.split(/\s+/);
  if (parts.length !== 5) {
    return false;
  }

  const patterns = [
    /^(\*|[0-9]|[1-5][0-9])(-(\*|[0-9]|[1-5][0-9]))?$/,
    /^(\*|[0-9]|[1-5][0-9])(-(\*|[0-9]|[1-5][0-9]))?(\/(\d+))?$/,
    /^(\*|[0-9]|[1-5][0-9])(,(\*|[0-9]|[1-5][0-9]))*$/,
    /^\*$|^\*\/[0-9]+$|^[0-9]+(-[0-9]+)?(\/[0-9]+)?$|^[0-9]+(,[0-9]+)*$/,
  ];

  for (let i = 0; i < 5; i++) {
    const part = parts[i];
    const valid = /^\*$|^\*\/[0-9]+$|^[0-9]+(-[0-9]+)?(\/[0-9]+)?$|^[0-9]+(,[0-9]+)*$/.test(part);
    if (!valid) {
      return false;
    }
  }

  return true;
}

export function extractCommandPath(command: string): string {
  const parts = command.split(/\s+/);
  let cmdPath = parts[0];

  if (cmdPath.startsWith('/')) {
    return cmdPath;
  }

  if (cmdPath.startsWith('=') || cmdPath.startsWith('$')) {
    const match = command.match(/^([^\s=]+=)[^\s]+/);
    if (match) {
      cmdPath = match[1];
    }
  }

  return cmdPath;
}

export function checkCommandPath(command: string, checkFn?: (p: string) => boolean): boolean {
  const cmdPath = extractCommandPath(command);

  if (!cmdPath.startsWith('/')) {
    return true;
  }

  if (cmdPath.includes('$') || cmdPath.includes('=')) {
    return true;
  }

  if (checkFn) {
    return checkFn(cmdPath);
  }

  try {
    return fs.existsSync(cmdPath);
  } catch {
    return false;
  }
}

export function detectSuspiciousModifications(job: CronJob): CronGuardIssue[] {
  const issues: CronGuardIssue[] = [];

  for (const { pattern, severity, description } of SUSPICIOUS_PATTERNS) {
    if (pattern.test(job.command)) {
      issues.push({
        type: 'suspicious',
        severity,
        jobId: job.id,
        message: description,
        details: `Line ${job.lineNumber}: ${job.rawLine}`,
      });
    }
  }

  return issues;
}

export function getSeverityForInterval(minutes: number): FrequencyAnalysis['severity'] {
  if (minutes <= 1) return 'CRITICAL';
  if (minutes <= 5) return 'HIGH';
  if (minutes <= 15) return 'MEDIUM';
  if (minutes <= 30) return 'LOW';
  return 'NORMAL';
}

export function analyzeCronFrequency(expression: string): FrequencyAnalysis | null {
  const parts = expression.split(/\s+/);
  if (parts.length !== 5) {
    return null;
  }

  const [minute, hour, , ,] = parts;

  // Detect wildcard minute with step (e.g., */5, */10, */15)
  const minuteStepMatch = minute.match(/^\*\/(\d+)$/);
  if (minuteStepMatch) {
    const interval = parseInt(minuteStepMatch[1], 10);
    if (interval <= 0 || interval > 59) {
      return null;
    }
    const runsPerDay = Math.floor(1440 / interval);

    return {
      expression,
      runsPerDay,
      intervalMinutes: interval,
      severity: getSeverityForInterval(interval),
      description: `Every ${interval} minute${interval > 1 ? 's' : ''} (${runsPerDay} runs/day)`,
    };
  }

  // Every minute wildcard (* * * * *)
  if (minute === '*' && hour === '*') {
    return {
      expression,
      runsPerDay: 1440,
      intervalMinutes: 1,
      severity: 'CRITICAL',
      description: 'Every minute (1440 runs/day) - malware beacon pattern',
    };
  }

  // Specific minutes list (e.g., 0,15,30,45 * * * * = every 15 min)
  const minuteListMatch = minute.match(/^(\d+,)*\d+$/);
  if (minuteListMatch && hour === '*') {
    const minutes = minute.split(',').map((m) => parseInt(m, 10)).filter((m) => m >= 0 && m <= 59);
    if (minutes.length > 1) {
      // Sort and find gaps
      minutes.sort((a, b) => a - b);
      let minGap = 60;
      for (let i = 0; i < minutes.length - 1; i++) {
        const gap = minutes[i + 1] - minutes[i];
        if (gap < minGap) minGap = gap;
      }
      // Also check wraparound gap
      const wraparoundGap = (60 - minutes[minutes.length - 1]) + minutes[0];
      if (wraparoundGap < minGap) minGap = wraparoundGap;

      const runsPerDay = minutes.length * 24;
      return {
        expression,
        runsPerDay,
        intervalMinutes: minGap,
        severity: getSeverityForInterval(minGap),
        description: `Every ${minGap} minute${minGap > 1 ? 's' : ''} (${runsPerDay} runs/day)`,
      };
    }
  }

  // Range with step (e.g., 0-30/5 * * * *)
  const rangeStepMatch = minute.match(/^(\d+)-(\d+)\/(\d+)$/);
  if (rangeStepMatch) {
    const [, startStr, endStr, stepStr] = rangeStepMatch;
    const start = parseInt(startStr, 10);
    const end = parseInt(endStr, 10);
    const step = parseInt(stepStr, 10);
    if (step > 0) {
      const runsPerDay = Math.floor(((end - start) / step) + 1) * 24;
      return {
        expression,
        runsPerDay,
        intervalMinutes: step,
        severity: getSeverityForInterval(step),
        description: `Every ${step} minute${step > 1 ? 's' : ''} during ${start}-${end} (${runsPerDay} runs/day)`,
      };
    }
  }

  // Single specific minute (e.g., 30 * * * * = every hour at :30)
  const singleMinuteMatch = minute.match(/^(\d+)$/);
  if (singleMinuteMatch && hour === '*') {
    const minuteVal = parseInt(singleMinuteMatch[1], 10);
    if (minuteVal >= 0 && minuteVal <= 59) {
      return {
        expression,
        runsPerDay: 24,
        intervalMinutes: 60,
        severity: 'NORMAL',
        description: 'Every hour at minute ' + minuteVal,
      };
    }
  }

  return null;
}

export function guardJobs(jobs: CronJob[], checkFn?: (p: string) => boolean): CronGuardResult {
  const issues: CronGuardIssue[] = [];

  for (const job of jobs) {
    if (!job.enabled) {
      issues.push({
        type: 'disabled',
        severity: 'HIGH',
        jobId: job.id,
        message: `Clean-sweep job ${job.id} is disabled`,
        details: `Line ${job.lineNumber}: ${job.rawLine}`,
      });
    }

    if (!isValidCronExpression(job.expression)) {
      issues.push({
        type: 'invalid_expression',
        severity: 'MEDIUM',
        jobId: job.id,
        message: `Job ${job.id} has invalid cron expression: ${job.expression}`,
        details: `Line ${job.lineNumber}: ${job.rawLine}`,
      });
    }

    if (!checkCommandPath(job.command, checkFn)) {
      issues.push({
        type: 'path_not_found',
        severity: 'HIGH',
        jobId: job.id,
        message: `Job ${job.id} references non-existent path: ${extractCommandPath(job.command)}`,
        details: `Line ${job.lineNumber}: ${job.rawLine}`,
      });
    }

    const suspiciousIssues = detectSuspiciousModifications(job);
    issues.push(...suspiciousIssues);

    // Check execution frequency
    const frequency = analyzeCronFrequency(job.expression);
    if (frequency && frequency.severity !== 'NORMAL') {
      issues.push({
        type: 'excessive_frequency',
        severity: frequency.severity as 'HIGH' | 'MEDIUM' | 'LOW',
        jobId: job.id,
        message: `Suspicious execution frequency: ${frequency.description}`,
        details: `Line ${job.lineNumber}: ${job.rawLine}`,
      });
    }
  }

  return {
    success: true,
    healthy: issues.length === 0,
    jobsChecked: jobs.length,
    jobs,
    issues,
  };
}

export function readCrontab(readFn?: () => string): string {
  if (readFn) {
    return readFn();
  }
  return '';
}

export function checkCrontabGuard(crontab: string, checkFn?: (p: string) => boolean): CronGuardResult {
  if (!crontab || crontab.trim() === '') {
    return {
      success: true,
      healthy: false,
      jobsChecked: 0,
      jobs: [],
      issues: [{
        type: 'missing',
        severity: 'HIGH',
        message: 'No crontab found or crontab is empty',
      }],
    };
  }

  const jobs = parseCrontab(crontab);

  if (jobs.length === 0) {
    return {
      success: true,
      healthy: false,
      jobsChecked: 0,
      jobs: [],
      issues: [{
        type: 'missing',
        severity: 'HIGH',
        message: 'No clean-sweep cron jobs found in crontab',
      }],
    };
  }

  return guardJobs(jobs, checkFn);
}

function formatOutput(data: unknown, useJson: boolean): void {
  if (useJson) {
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(data);
  }
}

function printResults(result: CronGuardResult): void {
  console.log('Clean Sweep Cron Guard');
  console.log('=====================');
  console.log(`\nTotal clean-sweep jobs checked: ${result.jobsChecked}`);

  if (result.jobs.length > 0) {
    console.log('\nClean-sweep Jobs:');
    console.log('-'.repeat(80));
    console.log(
      ' ' + 'ID'.padEnd(5) +
      'Status'.padEnd(10) +
      'Schedule'.padEnd(20) +
      'Command'
    );
    console.log('-'.repeat(80));

    for (const job of result.jobs) {
      const status = job.enabled ? 'enabled' : 'disabled';
      console.log(
        ' ' + String(job.id).padEnd(5) +
        status.padEnd(10) +
        job.expression.padEnd(20) +
        job.command
      );
    }
    console.log('-'.repeat(80));
  }

  if (result.issues.length === 0) {
    console.log('\nAll clean-sweep cron jobs are healthy.');
    return;
  }

  console.log(`\nIssues found: ${result.issues.length}`);

  const highSeverity = result.issues.filter((e) => e.severity === 'HIGH');
  const mediumSeverity = result.issues.filter((e) => e.severity === 'MEDIUM');
  const lowSeverity = result.issues.filter((e) => e.severity === 'LOW');

  if (highSeverity.length > 0) {
    console.log(`\n[HIGH severity: ${highSeverity.length}]`);
    for (const issue of highSeverity) {
      console.log(`  ${issue.message}`);
      if (issue.details) {
        console.log(`    ${issue.details}`);
      }
    }
  }

  if (mediumSeverity.length > 0) {
    console.log(`\n[MEDIUM severity: ${mediumSeverity.length}]`);
    for (const issue of mediumSeverity) {
      console.log(`  ${issue.message}`);
      if (issue.details) {
        console.log(`    ${issue.details}`);
      }
    }
  }

  if (lowSeverity.length > 0) {
    console.log(`\n[LOW severity: ${lowSeverity.length}]`);
    for (const issue of lowSeverity) {
      console.log(`  ${issue.message}`);
      if (issue.details) {
        console.log(`    ${issue.details}`);
      }
    }
  }
}

export function registerCronGuardCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  program
    .command('cron:guard')
    .description('Monitor clean-sweep cron jobs to ensure they are running properly')
    .option('--json', 'Output results as JSON', false)
    .action((cmdOptions) => {
      const opts = getOpts();
      const useJson = opts.json || cmdOptions.json;

      try {
        const crontab = readCrontab(() => {
          const { execSync } = require('child_process');
          try {
            return execSync('crontab -l', { encoding: 'utf-8' });
          } catch {
            return '';
          }
        });

        const result = checkCrontabGuard(crontab);

        if (useJson) {
          formatOutput(result, true);
        } else {
          printResults(result);
        }

        process.exit(result.healthy ? 0 : 1);
      } catch (err) {
        const error = {
          success: false,
          healthy: false,
          jobsChecked: 0,
          jobs: [],
          issues: [],
          message: String(err),
        };
        formatOutput(error, useJson);
        process.exit(1);
      }
    });
}
