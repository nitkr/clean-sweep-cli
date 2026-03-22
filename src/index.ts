#!/usr/bin/env node

import { Command } from 'commander';
import { registerScanCommand } from './commands/scan';
import { registerCoreRepairCommand } from './commands/core-repair';
import { registerPluginReinstallCommand } from './commands/plugin-reinstall';
import { registerFileExtractCommand } from './commands/file-extract';
import { registerDbScanCommand } from './commands/db-scan';
import { registerCleanupCommand } from './commands/cleanup';

export interface CliOptions {
  dryRun: boolean;
  force: boolean;
  json: boolean;
  path: string;
  verbose: boolean;
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
  .option('--verbose', 'Show detailed threat information', false);

registerScanCommand(program, getOpts);
registerCoreRepairCommand(program, getOpts);
registerPluginReinstallCommand(program, getOpts);
registerFileExtractCommand(program, getOpts);
registerDbScanCommand(program, getOpts);
registerCleanupCommand(program, getOpts);

program.parse(process.argv);

if (!process.argv.slice(2).length) {
  program.outputHelp();
}
