import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import fg from 'fast-glob';
import { detectThreats, Threat } from '../malware-scanner';
import { createLogger, LogLevel } from '../logger';

interface CliOptions {
  dryRun: boolean;
  force: boolean;
  json: boolean;
  path: string;
  verbose: boolean;
  logLevel: string;
}

interface QuarantineResult {
  success: boolean;
  dryRun: boolean;
  threatsFound: number;
  filesQuarantined: string[];
  quarantineDir: string | null;
  backupDir: string | null;
  errors: string[];
}

function formatOutput(data: unknown, useJson: boolean): void {
  if (useJson) {
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(data);
  }
}

async function scanForThreats(
  targetPath: string,
  verbose: boolean,
  logger: ReturnType<typeof createLogger>
): Promise<Threat[]> {
  const ignore = ['**/node_modules/**', '**/dist/**', '**/.git/**', '**/quarantine/**'];
  const files = await fg('**/*', {
    cwd: targetPath,
    absolute: true,
    onlyFiles: true,
    ignore,
  });

  const threats: Threat[] = [];
  const scanExtensions = ['.php', '.js'];

  logger.debug(`Scanning ${files.length} files in ${targetPath}`);

  for (const file of files) {
    const ext = path.extname(file).toLowerCase();
    if (!scanExtensions.includes(ext)) continue;

    try {
      const content = fs.readFileSync(file, 'utf-8');
      const fileThreats = detectThreats(file, content, verbose);
      if (fileThreats.length > 0) {
        logger.debug(`Found ${fileThreats.length} threats in ${file}`);
      }
      threats.push(...fileThreats);
    } catch (err) {
      logger.warn(`Failed to read file: ${file}`, { error: String(err) });
    }
  }

  return threats;
}

function copyFileToQuarantine(srcFile: string, quarantineDir: string, targetPath: string): string {
  const relativePath = path.relative(targetPath, srcFile);
  const destFile = path.join(quarantineDir, relativePath);
  const destDir = path.dirname(destFile);

  if (!fs.existsSync(destDir)) {
    fs.mkdirSync(destDir, { recursive: true });
  }

  fs.copyFileSync(srcFile, destFile);
  return destFile;
}

function createQuarantineBackup(
  infectedFiles: string[],
  targetPath: string
): { backupDir: string; backedUp: number } {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupDir = path.join(targetPath, 'quarantine-backup', timestamp);

  fs.mkdirSync(backupDir, { recursive: true });

  let backedUp = 0;
  for (const file of infectedFiles) {
    try {
      const relativePath = path.relative(targetPath, file);
      const destPath = path.join(backupDir, relativePath);
      const destDir = path.dirname(destPath);

      if (!fs.existsSync(destDir)) {
        fs.mkdirSync(destDir, { recursive: true });
      }

      fs.copyFileSync(file, destPath);
      backedUp++;
    } catch {
      // Skip files that can't be backed up
    }
  }

  return { backupDir, backedUp };
}

function moveToQuarantine(
  infectedFiles: string[],
  quarantineDir: string,
  targetPath: string
): { moved: string[]; errors: string[] } {
  const moved: string[] = [];
  const errors: string[] = [];

  for (const file of infectedFiles) {
    try {
      copyFileToQuarantine(file, quarantineDir, targetPath);
      fs.unlinkSync(file);
      moved.push(file);
    } catch (err) {
      errors.push(`Failed to quarantine ${file}: ${String(err)}`);
    }
  }

  return { moved, errors };
}

export function registerQuarantineCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  program
    .command('quarantine')
    .description('Quarantine infected files by moving them to a quarantine folder')
    .option('--path <path>', 'Directory to scan for threats')
    .option('--dry-run', 'Preview what would be quarantined without moving files', false)
    .option('--force', 'Actually quarantine infected files (requires explicit flag)', false)
    .option('--json', 'Output results as JSON', false)
    .option('--log-level <level>', 'Logging verbosity (debug, info, warn, error)', 'info')
    .action(async (cmdOptions) => {
      const opts = getOpts();
      const targetPath = path.resolve(cmdOptions.path || opts.path);
      const useJson = opts.json || cmdOptions.json;
      const logLevel = (cmdOptions.logLevel || opts.logLevel) as LogLevel;
      const logger = createLogger(logLevel);
      const dryRun = !cmdOptions.force && !opts.force;

      if (!fs.existsSync(targetPath)) {
        const error: QuarantineResult = {
          success: false,
          dryRun: true,
          threatsFound: 0,
          filesQuarantined: [],
          quarantineDir: null,
          backupDir: null,
          errors: [`Path does not exist: ${targetPath}`],
        };
        logger.error('Quarantine failed: path does not exist', { path: targetPath });
        formatOutput(error, useJson);
        process.exit(1);
      }

      const stats = fs.statSync(targetPath);
      if (!stats.isDirectory()) {
        const error: QuarantineResult = {
          success: false,
          dryRun: true,
          threatsFound: 0,
          filesQuarantined: [],
          quarantineDir: null,
          backupDir: null,
          errors: [`Path is not a directory: ${targetPath}`],
        };
        logger.error('Quarantine failed: path is not a directory', { path: targetPath });
        formatOutput(error, useJson);
        process.exit(1);
      }

      try {
        logger.info(`Scanning directory for threats: ${targetPath}`);
        const threats = await scanForThreats(targetPath, opts.verbose || cmdOptions.verbose, logger);

        const infectedFiles = [...new Set(threats.map(t => t.file))];

        if (threats.length === 0) {
          const result: QuarantineResult = {
            success: true,
            dryRun: true,
            threatsFound: 0,
            filesQuarantined: [],
            quarantineDir: null,
            backupDir: null,
            errors: [],
          };

          if (!useJson) {
            console.log('No threats found. Directory is clean.');
          }
          formatOutput(result, useJson);
          return;
        }

        if (dryRun) {
          const result: QuarantineResult = {
            success: true,
            dryRun: true,
            threatsFound: threats.length,
            filesQuarantined: infectedFiles,
            quarantineDir: null,
            backupDir: null,
            errors: [],
          };

          if (!useJson) {
            console.log(`Found ${threats.length} threat(s) in ${infectedFiles.length} file(s):`);
            for (const file of infectedFiles) {
              const fileThreats = threats.filter(t => t.file === file);
              console.log(`  - ${file} (${fileThreats.length} threat(s))`);
              for (const t of fileThreats) {
                console.log(`      [${t.type}] ${t.signature}`);
              }
            }
            console.log('\nDry run mode. Use --force to quarantine these files.');
          }
          formatOutput(result, useJson);
          return;
        }

        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const quarantineDir = path.join(targetPath, 'quarantine', timestamp);

        const backup = createQuarantineBackup(infectedFiles, targetPath);
        logger.info(`Created backup at ${backup.backupDir} (${backup.backedUp} files)`);

        fs.mkdirSync(quarantineDir, { recursive: true });

        const { moved, errors } = moveToQuarantine(infectedFiles, quarantineDir, targetPath);

        logger.info(`Quarantined ${moved.length} file(s) to ${quarantineDir}`);

        const result: QuarantineResult = {
          success: errors.length === 0,
          dryRun: false,
          threatsFound: threats.length,
          filesQuarantined: moved,
          quarantineDir,
          backupDir: backup.backupDir,
          errors,
        };

        if (!useJson) {
          console.log(`Quarantined ${moved.length} file(s) to: ${quarantineDir}`);
          console.log(`Backup created at: ${backup.backupDir}`);
          if (errors.length > 0) {
            console.log(`Errors: ${errors.length}`);
            for (const err of errors) {
              console.log(`  - ${err}`);
            }
          }
        }

        formatOutput(result, useJson);
      } catch (err) {
        const error: QuarantineResult = {
          success: false,
          dryRun: true,
          threatsFound: 0,
          filesQuarantined: [],
          quarantineDir: null,
          backupDir: null,
          errors: [`Quarantine failed: ${String(err)}`],
        };
        logger.error('Quarantine failed with error', { error: String(err) });
        formatOutput(error, useJson);
        process.exit(1);
      }
    });
}
