import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';

interface CliOptions {
  dryRun: boolean;
  force: boolean;
  json: boolean;
  path: string;
  verbose: boolean;
  logLevel: string;
}

interface QuarantineFolder {
  name: string;
  path: string;
  files: string[];
  createdAt: string;
}

interface RestoreResult {
  success: boolean;
  dryRun: boolean;
  quarantineFolders: QuarantineFolder[];
  selectedFolder: string | null;
  filesRestored: string[];
  errors: string[];
}

function formatOutput(data: unknown, useJson: boolean): void {
  if (useJson) {
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(data);
  }
}

function getQuarantineFolders(targetPath: string): QuarantineFolder[] {
  const quarantineBase = path.join(targetPath, 'clean-sweep-cli', 'quarantine');
  if (!fs.existsSync(quarantineBase) || !fs.statSync(quarantineBase).isDirectory()) {
    return [];
  }

  const entries = fs.readdirSync(quarantineBase, { withFileTypes: true });
  const folders: QuarantineFolder[] = [];

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;

    const folderPath = path.join(quarantineBase, entry.name);
    const files = listFilesRecursive(folderPath, folderPath);

    folders.push({
      name: entry.name,
      path: folderPath,
      files,
      createdAt: entry.name,
    });
  }

  return folders.sort((a, b) => a.name.localeCompare(b.name));
}

function listFilesRecursive(dir: string, baseDir: string): string[] {
  const results: string[] = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...listFilesRecursive(fullPath, baseDir));
    } else {
      results.push(path.relative(baseDir, fullPath));
    }
  }

  return results;
}

function restoreFiles(
  quarantineFolder: QuarantineFolder,
  targetPath: string
): { restored: string[]; errors: string[] } {
  const restored: string[] = [];
  const errors: string[] = [];

  for (const relativeFile of quarantineFolder.files) {
    // Validate path doesn't contain traversal sequences
    const normalizedRelative = path.normalize(relativeFile);
    if (normalizedRelative.startsWith('..') || path.isAbsolute(normalizedRelative)) {
      errors.push(`Invalid path traversal in ${relativeFile}: rejected`);
      continue;
    }

    const srcFile = path.join(quarantineFolder.path, relativeFile);
    const destFile = path.join(targetPath, relativeFile);
    
    // Ensure destFile is still within targetPath (prevent path traversal)
    const resolvedDest = path.resolve(destFile);
    const resolvedTarget = path.resolve(targetPath);
    if (!resolvedDest.startsWith(resolvedTarget + path.sep) && resolvedDest !== resolvedTarget) {
      errors.push(`Path traversal detected for ${relativeFile}: rejected`);
      continue;
    }

    const destDir = path.dirname(destFile);

    try {
      if (!fs.existsSync(destDir)) {
        fs.mkdirSync(destDir, { recursive: true });
      }

      fs.copyFileSync(srcFile, destFile);
      restored.push(relativeFile);
    } catch (err) {
      errors.push(`Failed to restore ${relativeFile}: ${String(err)}`);
    }
  }

  return { restored, errors };
}

export function registerRestoreCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  program
    .command('restore')
    .description('Restore quarantined files to their original locations')
    .option('--path <path>', 'Target path containing quarantine folder')
    .option('--folder <name>', 'Specific quarantine folder to restore from')
    .option('--dry-run', 'Preview what would be restored without moving files', false)
    .option('--force', 'Actually restore the files', false)
    .option('--json', 'Output results as JSON', false)
    .option('--log-level <level>', 'Logging verbosity (debug, info, warn, error)', 'info')
    .action(async (cmdOptions) => {
      const opts = getOpts();
      const targetPath = path.resolve(cmdOptions.path || opts.path);
      const useJson = opts.json || cmdOptions.json;
      const dryRun = (cmdOptions.dryRun || opts.dryRun) && !(cmdOptions.force || opts.force);
      const folderName = cmdOptions.folder || undefined;

      if (!fs.existsSync(targetPath)) {
        const error: RestoreResult = {
          success: false,
          dryRun: true,
          quarantineFolders: [],
          selectedFolder: null,
          filesRestored: [],
          errors: [`Path does not exist: ${targetPath}`],
        };
        formatOutput(error, useJson);
        process.exit(1);
      }

      if (!fs.statSync(targetPath).isDirectory()) {
        const error: RestoreResult = {
          success: false,
          dryRun: true,
          quarantineFolders: [],
          selectedFolder: null,
          filesRestored: [],
          errors: [`Path is not a directory: ${targetPath}`],
        };
        formatOutput(error, useJson);
        process.exit(1);
      }

      const folders = getQuarantineFolders(targetPath);

      if (folders.length === 0) {
        const result: RestoreResult = {
          success: true,
          dryRun: true,
          quarantineFolders: [],
          selectedFolder: null,
          filesRestored: [],
          errors: [],
        };

        if (!useJson) {
          console.log('No quarantine folders found.');
        }
        formatOutput(result, useJson);
        return;
      }

      if (!folderName) {
        const result: RestoreResult = {
          success: true,
          dryRun: true,
          quarantineFolders: folders,
          selectedFolder: null,
          filesRestored: [],
          errors: [],
        };

        if (!useJson) {
          console.log('Available quarantine folders:');
          for (const folder of folders) {
            console.log(`  - ${folder.name} (${folder.files.length} file(s))`);
          }
          console.log('\nUse --folder <name> to restore from a specific folder.');
        }
        formatOutput(result, useJson);
        return;
      }

      const selectedFolder = folders.find(f => f.name === folderName);
      if (!selectedFolder) {
        const error: RestoreResult = {
          success: false,
          dryRun: true,
          quarantineFolders: folders,
          selectedFolder: folderName,
          filesRestored: [],
          errors: [`Quarantine folder not found: ${folderName}`],
        };
        formatOutput(error, useJson);
        process.exit(1);
      }

      if (dryRun) {
        const result: RestoreResult = {
          success: true,
          dryRun: true,
          quarantineFolders: folders,
          selectedFolder: selectedFolder.name,
          filesRestored: selectedFolder.files,
          errors: [],
        };

        if (!useJson) {
          console.log(`Would restore ${selectedFolder.files.length} file(s) from "${selectedFolder.name}":`);
          for (const file of selectedFolder.files) {
            console.log(`  - ${file}`);
          }
          console.log('\nDry run mode. Use --force to actually restore these files.');
        }
        formatOutput(result, useJson);
        return;
      }

      const { restored, errors } = restoreFiles(selectedFolder, targetPath);

      const result: RestoreResult = {
        success: errors.length === 0,
        dryRun: false,
        quarantineFolders: folders,
        selectedFolder: selectedFolder.name,
        filesRestored: restored,
        errors,
      };

      if (!useJson) {
        console.log(`Restored ${restored.length} file(s) from "${selectedFolder.name}".`);
        if (errors.length > 0) {
          console.log(`Errors: ${errors.length}`);
          for (const err of errors) {
            console.log(`  - ${err}`);
          }
        }
      }

      formatOutput(result, useJson);
    });
}
