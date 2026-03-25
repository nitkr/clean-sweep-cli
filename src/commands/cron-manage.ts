import { Command } from 'commander';

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
}

export interface CronManageResult {
  success: boolean;
  action: 'list' | 'enable' | 'disable';
  jobs: CronJob[];
  message?: string;
}

const CLEAN_SWEEP_MARKER = '# clean-sweep';

function formatOutput(data: unknown, useJson: boolean): void {
  if (useJson) {
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(data);
  }
}

export function isCleanSweepLine(line: string): boolean {
  return line.includes('clean-sweep') && !line.startsWith('# ');
}

export function isDisabledCleanSweepLine(line: string): boolean {
  const trimmed = line.trimStart();
  // Any line starting with # that contains clean-sweep is considered disabled
  return trimmed.startsWith('#') && trimmed.includes('clean-sweep');
}

export function parseCrontab(crontab: string): CronJob[] {
  const lines = crontab.split('\n');
  const jobs: CronJob[] = [];
  let id = 0;

  for (const line of lines) {
    const trimmed = line.trim();

    // Skip empty lines and non-clean-sweep comments
    if (trimmed === '') {
      continue;
    }

    // Check if it's a disabled clean-sweep line (starts with # or # )
    const isDisabledLine = trimmed.startsWith('#') && trimmed.includes('clean-sweep');
    if (isDisabledLine) {
      // Remove all leading # characters and spaces
      const uncommented = trimmed.replace(/^#+\s*/, '');
      const parts = uncommented.split(/\s+/);
      if (parts.length >= 6) {
        jobs.push({ id: id++, expression: parts.slice(0, 5).join(' '), command: parts.slice(5).join(' '), enabled: false, rawLine: trimmed });
      }
      continue;
    }

    // Check if it's an enabled clean-sweep line
    if (isCleanSweepLine(trimmed)) {
      const parts = trimmed.split(/\s+/);
      const expression = parts.slice(0, 5).join(' ');
      const command = parts.slice(5).join(' ');
      jobs.push({ id: id++, expression, command, enabled: true, rawLine: trimmed });
    }
  }

  return jobs;
}

export function toggleCronJob(
  crontab: string,
  jobId: number,
  enable: boolean
): { updated: string; job: CronJob | null } {
  const lines = crontab.split('\n');
  let currentId = 0;

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();

    if (isCleanSweepLine(trimmed) || isDisabledCleanSweepLine(trimmed)) {
      if (currentId === jobId) {
        if (enable && isDisabledCleanSweepLine(trimmed)) {
          const uncommented = trimmed.replace(/^#+\s*/, '');
          const indent = lines[i].match(/^(\s*)/)?.[1] || '';
          lines[i] = indent + uncommented;
          const parts = uncommented.split(/\s+/);
          return {
            updated: lines.join('\n'),
            job: {
              id: jobId,
              expression: parts.slice(0, 5).join(' '),
              command: parts.slice(5).join(' '),
              enabled: true,
              rawLine: uncommented,
            },
          };
        } else if (!enable && isCleanSweepLine(trimmed)) {
          const indent = lines[i].match(/^(\s*)/)?.[1] || '';
          lines[i] = indent + '# ' + trimmed;
          const parts = trimmed.split(/\s+/);
          return {
            updated: lines.join('\n'),
            job: {
              id: jobId,
              expression: parts.slice(0, 5).join(' '),
              command: parts.slice(5).join(' '),
              enabled: false,
              rawLine: '# ' + trimmed,
            },
          };
        }
        return { updated: crontab, job: parseCrontab(crontab).find(j => j.id === jobId) || null };
      }
      currentId++;
    }
  }

  return { updated: crontab, job: null };
}

export function readCrontab(readFn?: () => string): string {
  if (readFn) return readFn();
  return '';
}

export function writeCrontab(content: string, writeFn?: (c: string) => void): void {
  if (writeFn) {
    writeFn(content);
  }
}

export function listJobs(crontab: string): CronManageResult {
  const jobs = parseCrontab(crontab);
  return { success: true, action: 'list', jobs };
}

export function enableJob(crontab: string, jobId: number): CronManageResult & { updatedCrontab: string } {
  const { updated, job } = toggleCronJob(crontab, jobId, true);
  if (!job) {
    return { success: false, action: 'enable', jobs: [], message: `Job with id ${jobId} not found`, updatedCrontab: crontab };
  }
  return { success: true, action: 'enable', jobs: [job], message: `Job ${jobId} enabled`, updatedCrontab: updated };
}

export function disableJob(crontab: string, jobId: number): CronManageResult & { updatedCrontab: string } {
  const { updated, job } = toggleCronJob(crontab, jobId, false);
  if (!job) {
    return { success: false, action: 'disable', jobs: [], message: `Job with id ${jobId} not found`, updatedCrontab: crontab };
  }
  return { success: true, action: 'disable', jobs: [job], message: `Job ${jobId} disabled`, updatedCrontab: updated };
}

function printJobs(jobs: CronJob[]): void {
  console.log('Clean Sweep Cron Jobs');
  console.log('====================');

  if (jobs.length === 0) {
    console.log('\nNo clean-sweep cron jobs found.');
    return;
  }

  console.log('\n' + '-'.repeat(80));
  console.log(
    ' ' + 'ID'.padEnd(5) +
    'Status'.padEnd(10) +
    'Schedule'.padEnd(20) +
    'Command'
  );
  console.log('-'.repeat(80));

  for (const job of jobs) {
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

export function registerCronManageCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  const cronManage = program
    .command('cron:manage')
    .description('Manage clean-sweep cron jobs');

  cronManage
    .command('list')
    .description('List all clean-sweep cron jobs')
    .option('--json', 'Output results as JSON', false)
    .action((cmdOptions) => {
      const opts = getOpts();
      const useJson = opts.json || cmdOptions.json;

      try {
        const crontab = readCrontab(() => {
          const { execSync } = require('child_process');
          try {
            return execSync('crontab -l 2>/dev/null', { encoding: 'utf-8' });
          } catch {
            return '';
          }
        });

        const result = listJobs(crontab);

        if (useJson) {
          formatOutput(result, true);
          return;
        }

        printJobs(result.jobs);
      } catch (err) {
        const error = { success: false, error: 'Failed to list cron jobs', message: String(err) };
        formatOutput(error, useJson);
        process.exit(1);
      }
    });

  cronManage
    .command('enable <id>')
    .description('Enable a disabled clean-sweep cron job')
    .option('--json', 'Output results as JSON', false)
    .action((id, cmdOptions) => {
      const opts = getOpts();
      const useJson = opts.json || cmdOptions.json;

      try {
        const jobId = parseInt(id, 10);
        if (isNaN(jobId)) {
          const error = { success: false, error: 'Invalid job id', message: `Expected a number, got: ${id}` };
          formatOutput(error, useJson);
          process.exit(1);
        }

        let crontab = readCrontab(() => {
          const { execSync } = require('child_process');
          try {
            return execSync('crontab -l 2>/dev/null', { encoding: 'utf-8' });
          } catch {
            return '';
          }
        });

        const result = enableJob(crontab, jobId);

        if (result.success) {
          writeCrontab(result.updatedCrontab, (content) => {
            const { execSync } = require('child_process');
            execSync('crontab -', { input: content });
          });
        }

        if (useJson) {
          formatOutput(result, true);
          return;
        }

        if (result.success) {
          console.log(result.message);
        } else {
          console.error(result.message);
          process.exit(1);
        }
      } catch (err) {
        const error = { success: false, error: 'Failed to enable cron job', message: String(err) };
        formatOutput(error, useJson);
        process.exit(1);
      }
    });

  cronManage
    .command('disable <id>')
    .description('Disable an active clean-sweep cron job')
    .option('--json', 'Output results as JSON', false)
    .action((id, cmdOptions) => {
      const opts = getOpts();
      const useJson = opts.json || cmdOptions.json;

      try {
        const jobId = parseInt(id, 10);
        if (isNaN(jobId)) {
          const error = { success: false, error: 'Invalid job id', message: `Expected a number, got: ${id}` };
          formatOutput(error, useJson);
          process.exit(1);
        }

        let crontab = readCrontab(() => {
          const { execSync } = require('child_process');
          try {
            return execSync('crontab -l 2>/dev/null', { encoding: 'utf-8' });
          } catch {
            return '';
          }
        });

        const result = disableJob(crontab, jobId);

        if (result.success) {
          writeCrontab(result.updatedCrontab, (content) => {
            const { execSync } = require('child_process');
            execSync('crontab -', { input: content });
          });
        }

        if (useJson) {
          formatOutput(result, true);
          return;
        }

        if (result.success) {
          console.log(result.message);
        } else {
          console.error(result.message);
          process.exit(1);
        }
      } catch (err) {
        const error = { success: false, error: 'Failed to disable cron job', message: String(err) };
        formatOutput(error, useJson);
        process.exit(1);
      }
    });
}
