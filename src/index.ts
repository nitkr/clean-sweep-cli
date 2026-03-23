#!/usr/bin/env node

import { Command } from 'commander';
import { registerScanCommand } from './commands/scan';
import { registerCoreRepairCommand } from './commands/core-repair';
import { registerPluginReinstallCommand } from './commands/plugin-reinstall';
import { registerFileExtractCommand } from './commands/file-extract';
import { registerDbScanCommand } from './commands/db-scan';
import { registerCleanupCommand } from './commands/cleanup';
import { registerStatusCommand } from './commands/status';
import { registerUpdateSignaturesCommand } from './commands/update-signatures';
import { registerListSignaturesCommand } from './commands/list-signatures';
import { registerSummaryCommand } from './commands/summary';
import { registerQuarantineCommand } from './commands/quarantine';
import { registerRestoreCommand } from './commands/restore';
import { registerScheduleCommand } from './commands/schedule';
import { registerDepsCheckCommand } from './commands/deps-check';

export interface CliOptions {
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

const program = new Command();

let cachedOpts: CliOptions | null = null;

function getOpts(): CliOptions {
  if (!cachedOpts) {
    cachedOpts = program.opts() as CliOptions;
  }
  return cachedOpts;
}

program
  .name('clean-sweep')
  .description('CLI tool for cleaning and managing project files')
  .version('1.0.0')
  .option('--dry-run', 'Preview changes without applying them', true)
  .option('--force', 'Skip confirmation prompts', false)
  .option('--json', 'Output results as JSON', false)
  .option('--path <path>', 'Target path to operate on', process.cwd())
  .option('--verbose', 'Show detailed threat information', false)
  .option('--check-vulnerabilities', 'Check for known WordPress vulnerabilities', false)
  .option('--check-integrity', 'Check WordPress core file integrity', false)
  .option('--find-unknown', 'Find unknown files not part of WordPress core', false)
  .option('--report', 'Save JSON report to file', false)
  .option('--html-report', 'Save HTML report to file', false)
  .option('--log-level <level>', 'Logging verbosity (debug, info, warn, error)', 'info');

registerScanCommand(program, getOpts);
registerCoreRepairCommand(program, getOpts);
registerPluginReinstallCommand(program, getOpts);
registerFileExtractCommand(program, getOpts);
registerDbScanCommand(program, getOpts);
registerCleanupCommand(program, getOpts);
registerStatusCommand(program, getOpts);
registerUpdateSignaturesCommand(program, getOpts);
registerListSignaturesCommand(program, getOpts);
registerSummaryCommand(program, getOpts);
registerQuarantineCommand(program, getOpts);
registerRestoreCommand(program, getOpts);
registerScheduleCommand(program, getOpts);
registerDepsCheckCommand(program, getOpts);

program.parse(process.argv);

if (!process.argv.slice(2).length) {
  program.outputHelp();
}
