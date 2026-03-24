import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';

interface CliOptions {
  dryRun: boolean;
  force: boolean;
  json: boolean;
  path: string;
  verbose: boolean;
}

function formatOutput(data: unknown, useJson: boolean): void {
  if (useJson) {
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(data);
  }
}

export function registerCleanupCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  program
    .command('cleanup')
    .description('Remove Clean Sweep toolkit files from a WordPress installation')
    .option('--path <path>', 'WordPress installation path')
    .option('--force', 'Actually remove the files (required - never runs automatically)', false)
    .action(async (cmdOptions) => {
      const opts = getOpts();
      const targetPath = path.resolve(opts.path || cmdOptions.path);
      const force = opts.force || cmdOptions.force;
      const dryRun = opts.dryRun && !force;

      if (!force && !dryRun) {
        const error = { 
          success: false, 
          error: 'Cleanup requires --force flag. This command will remove toolkit files.',
          dryRun: true,
        };
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      }

      if (!fs.existsSync(targetPath)) {
        const error = { success: false, error: 'Path does not exist', path: targetPath };
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      }

      const filesToRemove: string[] = [];

      const parentDir = path.dirname(targetPath);
      const backupsPath = path.join(parentDir, 'backups');
      if (fs.existsSync(backupsPath)) {
        const entries = fs.readdirSync(backupsPath);
        for (const entry of entries) {
          const fullPath = path.join(backupsPath, entry);
          filesToRemove.push(fullPath);
        }
      }

      const tempDir = os.tmpdir();
      const tempPrefixes = ['wp-core-', 'wp-plugin-', 'clean-sweep-'];
      try {
        const tempEntries = fs.readdirSync(tempDir);
        for (const entry of tempEntries) {
          for (const prefix of tempPrefixes) {
            if (entry.startsWith(prefix)) {
              filesToRemove.push(path.join(tempDir, entry));
              break;
            }
          }
        }
      } catch {
        // Ignore temp dir read errors
      }

      const result = {
        success: true,
        removedFiles: [] as string[],
        dryRun: dryRun,
      };

      if (filesToRemove.length === 0) {
        if (!opts.json && !cmdOptions.json) {
          console.log('No Clean Sweep toolkit files found to remove.');
        }
        formatOutput(result, opts.json || cmdOptions.json);
        return;
      }

      if (!opts.json && !cmdOptions.json) {
        console.log(`Found ${filesToRemove.length} item(s) to remove:`);
        for (const file of filesToRemove) {
          console.log(`  - ${file}`);
        }
      }

      if (dryRun) {
        if (!opts.json && !cmdOptions.json) {
          console.log(`(Dry run) Would remove ${filesToRemove.length} item(s).`);
        }
        result.removedFiles = filesToRemove;
        formatOutput(result, opts.json || cmdOptions.json);
        return;
      }

      for (const file of filesToRemove) {
        try {
          const stat = fs.statSync(file);
          if (stat.isDirectory()) {
            fs.rmSync(file, { recursive: true, force: true });
          } else {
            fs.unlinkSync(file);
          }
          result.removedFiles.push(file);
        } catch {
          // Skip files that can't be removed
        }
      }

      if (!opts.json && !cmdOptions.json) {
        console.log(`Removed ${result.removedFiles.length} item(s).`);
      }

      formatOutput(result, opts.json || cmdOptions.json);
    });
}
