import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import AdmZip from 'adm-zip';
import { isWordPressInstallation } from '../wp-file-detector';

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

export function copyDirRecursive(src: string, dest: string): void {
  fs.mkdirSync(dest, { recursive: true });
  const entries = fs.readdirSync(src);
  for (const entry of entries) {
    const srcPath = path.join(src, entry);
    const destPath = path.join(dest, entry);
    const stat = fs.statSync(srcPath);
    if (stat.isDirectory()) {
      copyDirRecursive(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

export function getAllFiles(dir: string): string[] {
  const files: string[] = [];
  const entries = fs.readdirSync(dir);
  for (const entry of entries) {
    const fullPath = path.join(dir, entry);
    const stat = fs.statSync(fullPath);
    if (stat.isDirectory()) {
      files.push(...getAllFiles(fullPath));
    } else {
      files.push(fullPath);
    }
  }
  return files;
}

export function registerFileExtractCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  program
    .command('file:extract')
    .description('Extract a ZIP file to a WordPress folder')
    .option('--path <path>', 'WordPress installation path')
    .option('--zip <path>', 'Path to ZIP file to extract (required)')
    .option('--target <dir>', 'Target directory (default: wp-content/uploads/)', 'wp-content/uploads/')
    .option('--dry-run', 'Preview changes without applying them', true)
    .option('--force', 'Actually extract the ZIP file', false)
    .action(async (cmdOptions) => {
      const opts = getOpts();
      const wpPath = path.resolve(cmdOptions.path || opts.path || process.cwd());
      const zipPath = cmdOptions.zip;
      const targetDir = cmdOptions.target || 'wp-content/uploads/';
      const dryRun = cmdOptions.force ? false : (opts.dryRun || cmdOptions.dryRun);

      if (!zipPath) {
        const error = { success: false, error: 'ZIP file path is required. Use --zip <path>' };
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      }

      if (!fs.existsSync(wpPath)) {
        const error = { success: false, error: 'WordPress path does not exist', path: wpPath };
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      }

      if (!isWordPressInstallation(wpPath)) {
        const error = { success: false, error: 'Path is not a valid WordPress installation', path: wpPath };
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      }

      if (!fs.existsSync(zipPath)) {
        const error = { success: false, error: 'ZIP file does not exist', zipPath };
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      }

      const targetPath = path.join(wpPath, targetDir);
      const targetExists = fs.existsSync(targetPath);

      let extractedFiles: string[] = [];
      let backupPath: string | null = null;

      try {
        const zip = new AdmZip(zipPath);
        const zipEntries = zip.getEntries();
        const tempExtractDir = fs.mkdtempSync(path.join(process.env.TEMP || '/tmp', 'clean-sweep-extract-'));

        try {
          zip.extractAllTo(tempExtractDir, true);
          const tempExtractedFiles = getAllFiles(tempExtractDir);
          extractedFiles = tempExtractedFiles.map(f => path.relative(tempExtractDir, f));

          if (dryRun) {
            console.log(`\n[DRY RUN] Would extract ZIP: ${zipPath}`);
            console.log(`[DRY RUN] Target directory: ${targetPath}`);
            console.log(`[DRY RUN] Would extract ${extractedFiles.length} file(s):`);
            for (const file of extractedFiles.slice(0, 10)) {
              console.log(`  - ${file}`);
            }
            if (extractedFiles.length > 10) {
              console.log(`  ... and ${extractedFiles.length - 10} more`);
            }
            if (targetExists) {
              console.log(`[DRY RUN] Target exists - would create backup before extraction`);
            }
          } else {
            if (targetExists) {
              const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
              backupPath = path.join(path.dirname(targetPath), 'backups', `extract-${path.basename(targetDir)}-${timestamp}`);
              fs.mkdirSync(backupPath, { recursive: true });
              copyDirRecursive(targetPath, backupPath);
              console.log(`Backup created at: ${backupPath}`);
            }

            fs.mkdirSync(targetPath, { recursive: true });
            copyDirRecursive(tempExtractDir, targetPath);
            console.log(`Extracted ${extractedFiles.length} file(s) to: ${targetPath}`);
          }

          const result = {
            success: true,
            zipPath: path.resolve(zipPath),
            targetPath: path.resolve(targetPath),
            extractedFiles,
            backupPath,
            dryRun,
          };

          formatOutput(result, opts.json || cmdOptions.json);
        } finally {
          fs.rmSync(tempExtractDir, { recursive: true, force: true });
        }
      } catch (err) {
        const error = {
          success: false,
          zipPath: path.resolve(zipPath),
          targetPath: path.resolve(targetPath),
          error: String(err),
          dryRun,
        };
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      }
    });
}
