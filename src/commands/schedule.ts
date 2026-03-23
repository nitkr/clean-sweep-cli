import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';

interface CliOptions {
  dryRun: boolean;
  force: boolean;
  json: boolean;
  path: string;
  verbose: boolean;
}

type ScheduleFrequency = 'daily' | 'weekly' | 'monthly';

interface CronConfig {
  expression: string;
  command: string;
  frequency: ScheduleFrequency;
  description: string;
}

interface ScheduleResult {
  success: boolean;
  frequency: ScheduleFrequency;
  targetPath: string;
  cronConfig: CronConfig;
  scriptPath: string;
  cronLine: string;
}

function formatOutput(data: unknown, useJson: boolean): void {
  if (useJson) {
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(data);
  }
}

export function getCronExpression(frequency: ScheduleFrequency): string {
  switch (frequency) {
    case 'daily':
      return '0 2 * * *';
    case 'weekly':
      return '0 3 * * 0';
    case 'monthly':
      return '0 4 1 * *';
  }
}

export function getFrequencyDescription(frequency: ScheduleFrequency): string {
  switch (frequency) {
    case 'daily':
      return 'Every day at 2:00 AM';
    case 'weekly':
      return 'Every Sunday at 3:00 AM';
    case 'monthly':
      return '1st of each month at 4:00 AM';
  }
}

export function buildCronConfig(
  frequency: ScheduleFrequency,
  targetPath: string,
  scriptPath: string
): CronConfig {
  const expression = getCronExpression(frequency);
  const command = `/bin/bash ${scriptPath}`;
  const description = getFrequencyDescription(frequency);

  return { expression, command, frequency, description };
}

export function buildCronLine(config: CronConfig): string {
  return `${config.expression} ${config.command}`;
}

export function generateShellScript(targetPath: string, logDir: string): string {
  const safePath = targetPath.replace(/'/g, "'\\''");
  const safeLogDir = logDir.replace(/'/g, "'\\''");
  const D = '$';

  return [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    '',
    "SCAN_PATH='" + safePath + "'",
    "LOG_DIR='" + safeLogDir + "'",
    'TIMESTAMP=$(date +"%Y%m%d_%H%M%S")',
    'LOG_FILE="' + D + '{LOG_DIR}/clean-sweep-' + D + '{TIMESTAMP}.log"',
    '',
    'mkdir -p "' + D + '{LOG_DIR}"',
    '',
    'echo "Clean Sweep scheduled scan started at $(date)" | tee "' + D + '{LOG_FILE}"',
    'echo "Scanning: ' + D + '{SCAN_PATH}" | tee -a "' + D + '{LOG_FILE}"',
    '',
    'clean-sweep scan --path "' + D + '{SCAN_PATH}" --json --report 2>&1 | tee -a "' + D + '{LOG_FILE}"',
    'EXIT_CODE=' + D + '{PIPESTATUS[0]}',
    '',
    'if [ ' + D + '{EXIT_CODE} -eq 0 ]; then',
    '  echo "Scan completed successfully at $(date)" | tee -a "' + D + '{LOG_FILE}"',
    'else',
    '  echo "Scan completed with exit code ' + D + '{EXIT_CODE} at $(date)" | tee -a "' + D + '{LOG_FILE}"',
    'fi',
    '',
    '# Keep only the last 30 log files',
    'cd "' + D + '{LOG_DIR}"',
    'ls -t clean-sweep-*.log 2>/dev/null | tail -n +31 | xargs -r rm --',
    '',
    'exit ' + D + '{EXIT_CODE}',
    '',
  ].join('\n');
}

export function writeShellScript(scriptContent: string, scriptPath: string): void {
  fs.writeFileSync(scriptPath, scriptContent, { mode: 0o755 });
}

export function registerScheduleCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  program
    .command('schedule')
    .description('Generate cron job configuration for periodic malware scans')
    .option('--path <path>', 'Directory to scan')
    .option('--daily', 'Schedule daily scans (2:00 AM)')
    .option('--weekly', 'Schedule weekly scans (Sunday 3:00 AM)')
    .option('--monthly', 'Schedule monthly scans (1st at 4:00 AM)')
    .option('--output-dir <dir>', 'Directory to write scripts and logs')
    .option('--json', 'Output results as JSON', false)
    .action(async (cmdOptions) => {
      const opts = getOpts();
      const targetPath = path.resolve(cmdOptions.path || opts.path);
      const useJson = opts.json || cmdOptions.json;

      if (!fs.existsSync(targetPath)) {
        const error = { success: false, error: 'Path does not exist', path: targetPath };
        formatOutput(error, useJson);
        process.exit(1);
      }

      const stats = fs.statSync(targetPath);
      if (!stats.isDirectory()) {
        const error = { success: false, error: 'Path is not a directory', path: targetPath };
        formatOutput(error, useJson);
        process.exit(1);
      }

      const frequency: ScheduleFrequency | undefined = cmdOptions.daily
        ? 'daily'
        : cmdOptions.weekly
          ? 'weekly'
          : cmdOptions.monthly
            ? 'monthly'
            : undefined;

      if (!frequency) {
        const error = {
          success: false,
          error: 'Please specify a schedule frequency: --daily, --weekly, or --monthly',
        };
        formatOutput(error, useJson);
        process.exit(1);
      }

      const outputDir = path.resolve(
        cmdOptions.outputDir || path.join(targetPath, '..', 'clean-sweep-schedule')
      );

      if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
      }

      const logDir = path.join(outputDir, 'logs');
      if (!fs.existsSync(logDir)) {
        fs.mkdirSync(logDir, { recursive: true });
      }

      const scriptName = `clean-sweep-${frequency}.sh`;
      const scriptPath = path.join(outputDir, scriptName);

      const scriptContent = generateShellScript(targetPath, logDir);

      const cronConfig = buildCronConfig(frequency, targetPath, scriptPath);
      const cronLine = buildCronLine(cronConfig);

      const result: ScheduleResult = {
        success: true,
        frequency,
        targetPath,
        cronConfig,
        scriptPath,
        cronLine,
      };

      if (!useJson) {
        console.log('Scheduled Scan Configuration');
        console.log('==========================');
        console.log(`Frequency: ${frequency}`);
        console.log(`Target: ${targetPath}`);
        console.log(`Schedule: ${cronConfig.description}`);
        console.log(`Cron: ${cronLine}`);
        console.log(`Script: ${scriptPath}`);
        console.log(`Logs: ${logDir}`);
        console.log('');
        console.log('To install, run:');
        console.log(`  (crontab -l 2>/dev/null; echo "${cronLine}") | crontab -`);
        console.log('');
        console.log('Generated shell script:');
        console.log(scriptContent);
      }

      writeShellScript(scriptContent, scriptPath);

      formatOutput(result, useJson);
    });
}
