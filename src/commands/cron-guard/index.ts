import { Command } from 'commander';
import { CronGuardResult, CliOptions } from './types';
import { readCrontab, checkCrontabGuard, formatOutput, printResults } from './parser';
import { purgeOrphanedCronJobs } from './purge';

export function registerCronGuardCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  const cronGuardCmd = program
    .command('cron:guard')
    .description('Monitor clean-sweep cron jobs to ensure they are running properly')
    .option('--json', 'Output results as JSON', false);

  cronGuardCmd
    .command('purge')
    .description('Purge orphaned WordPress cron tasks from deleted plugins (nuclear option)')
    .option('--dry-run', 'Preview what would be deleted without deleting', false)
    .option('--force', 'Actually perform the deletion (required)', false)
    .option('--exclude <hooks>', 'Comma-separated hooks to exclude from deletion')
    .option('--only-suspicious', 'Only purge suspicious/malicious hooks, keep all others', false)
    .option('--path <path>', 'WordPress installation path')
    .action(async (cmdOptions) => {
      const opts = getOpts();
      const useJson = opts.json || cmdOptions.json;
      const targetPath = cmdOptions.path || opts.path;

      if (!targetPath) {
        const error = {
          success: false,
          message: 'WordPress path not specified. Use --path or run from WordPress directory.',
        };
        formatOutput(error, useJson);
        process.exit(1);
      }

      const dryRun = cmdOptions.dryRun || (opts.dryRun && !cmdOptions.force && !opts.force);
      const force = cmdOptions.force || opts.force;

      if (!dryRun && !force) {
        const error = {
          success: false,
          message: 'This command requires either --dry-run or --force flag. Use --dry-run to preview, --force to execute.',
        };
        formatOutput(error, useJson);
        process.exit(1);
      }

      try {
        const excludeHooks = cmdOptions.exclude
          ? cmdOptions.exclude.split(',').map((h: string) => h.trim()).filter(Boolean)
          : [];

        const result = await purgeOrphanedCronJobs(targetPath, {
          dryRun,
          excludeHooks,
          onlySuspicious: cmdOptions.onlySuspicious,
        });

        if (useJson) {
          formatOutput(result, true);
        } else if (!useJson) {
          console.log('Clean Sweep Cron Purge');
          console.log('======================');
          console.log(`\n${result.message}`);
          console.log(`\nTotal hooks: ${result.totalHooks}`);
          console.log(`Hooks deleted: ${result.hooksDeleted}`);
          console.log(`Hooks preserved: ${result.hooksPreserved}`);

          if (result.deletedHooks.length > 0) {
            console.log('\nDeleted hooks:');
            for (const hook of result.deletedHooks) {
              console.log(`  - ${hook}`);
            }
          }

          if (result.hooksPreserved > 0 && dryRun) {
            console.log('\nPreserved hooks (sample):');
            const sample = result.preservedHooks.slice(0, 10);
            for (const hook of sample) {
              console.log(`  - ${hook}`);
            }
            if (result.preservedHooks.length > 10) {
              console.log(`  ... and ${result.preservedHooks.length - 10} more`);
            }
          }
        }

        process.exit(result.success ? 0 : 1);
      } catch (err) {
        const error = {
          success: false,
          message: String(err),
        };
        formatOutput(error, useJson);
        process.exit(1);
      }
    });

  cronGuardCmd.action((cmdOptions) => {
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

      const result = checkCrontabGuard(crontab);

      if (useJson) {
        formatOutput(result, true);
      } else if (!useJson) {
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
