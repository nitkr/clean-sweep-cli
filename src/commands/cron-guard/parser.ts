import * as fs from 'fs';
import {
  CronJob,
  CronGuardIssue,
  CronGuardResult,
  CLEAN_SWEEP_MARKER,
  SUSPICIOUS_PATTERNS,
  FrequencyAnalysis,
} from './types';

export { CronJob, CronGuardIssue, CronGuardResult, FrequencyAnalysis };

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

  if (minute === '*' && hour === '*') {
    return {
      expression,
      runsPerDay: 1440,
      intervalMinutes: 1,
      severity: 'CRITICAL',
      description: 'Every minute (1440 runs/day) - malware beacon pattern',
    };
  }

  const minuteListMatch = minute.match(/^(\d+,)*\d+$/);
  if (minuteListMatch && hour === '*') {
    const minutes = minute.split(',').map((m) => parseInt(m, 10)).filter((m) => m >= 0 && m <= 59);
    if (minutes.length > 1) {
      minutes.sort((a, b) => a - b);
      let minGap = 60;
      for (let i = 0; i < minutes.length - 1; i++) {
        const gap = minutes[i + 1] - minutes[i];
        if (gap < minGap) minGap = gap;
      }
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

export { formatOutput, printResults };
