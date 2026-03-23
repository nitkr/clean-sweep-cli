import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import fg from 'fast-glob';
import { detectThreats, Threat } from '../malware-scanner';
import { createLogger, LogLevel, generateReport, saveReport, getDefaultReportPath } from '../logger';
import { loadWhitelist, applyWhitelist, WhitelistConfig } from '../whitelist';

interface ScanBatchCliOptions {
  dryRun: boolean;
  json: boolean;
  path: string;
  verbose: boolean;
  logLevel: string;
}

interface DirectoryResult {
  path: string;
  totalFiles: number;
  totalDirectories: number;
  threats: Threat[];
  safe: boolean;
  whitelisted: number;
}

interface BatchReport {
  timestamp: string;
  directories: DirectoryResult[];
  totalDirectories: number;
  totalFiles: number;
  totalThreats: number;
  totalWhitelisted: number;
  safeDirectories: number;
  unsafeDirectories: number;
  overallSafe: boolean;
}

function formatOutput(data: unknown, useJson: boolean): void {
  if (useJson) {
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(data);
  }
}

function readDirectoryListFile(filePath: string): string[] {
  const resolved = path.resolve(filePath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`List file does not exist: ${resolved}`);
  }
  const content = fs.readFileSync(resolved, 'utf-8');
  return content
    .split('\n')
    .map(line => line.trim())
    .filter(line => line.length > 0 && !line.startsWith('#'));
}

function scanSingleDirectory(
  targetPath: string,
  options: { verbose: boolean; dryRun: boolean },
  logger: ReturnType<typeof createLogger>,
  whitelist?: WhitelistConfig
): DirectoryResult {
  const ignore = ['**/node_modules/**', '**/dist/**', '**/.git/**'];
  const files = fg.sync('**/*', { cwd: targetPath, absolute: true, onlyFiles: true, ignore });
  const directories = fg.sync('**/*', { cwd: targetPath, absolute: true, onlyDirectories: true, ignore });

  const threats: Threat[] = [];
  const scanExtensions = ['.php', '.js'];

  logger.debug(`Scanning ${files.length} files in ${targetPath}`);

  for (const file of files) {
    const ext = path.extname(file).toLowerCase();
    if (!scanExtensions.includes(ext)) continue;

    try {
      const content = fs.readFileSync(file, 'utf-8');
      const fileThreats = detectThreats(file, content, options.verbose);
      if (fileThreats.length > 0) {
        logger.debug(`Found ${fileThreats.length} threats in ${file}`);
      }
      threats.push(...fileThreats);
    } catch (err) {
      logger.warn(`Failed to read file: ${file}`, { error: String(err) });
    }
  }

  const totalBeforeWhitelist = threats.length;
  let filteredThreats = threats;
  let whitelistedCount = 0;

  if (whitelist) {
    filteredThreats = applyWhitelist(threats, whitelist);
    whitelistedCount = totalBeforeWhitelist - filteredThreats.length;
    if (whitelistedCount > 0) {
      logger.info(`Whitelist filtered out ${whitelistedCount} threat(s)`);
    }
  }

  return {
    path: targetPath,
    totalFiles: files.length,
    totalDirectories: directories.length,
    threats: filteredThreats,
    safe: filteredThreats.length === 0,
    whitelisted: whitelistedCount,
  };
}

function buildBatchReport(results: DirectoryResult[]): BatchReport {
  const totalThreats = results.reduce((sum, r) => sum + r.threats.length, 0);
  const totalWhitelisted = results.reduce((sum, r) => sum + r.whitelisted, 0);
  const totalFiles = results.reduce((sum, r) => sum + r.totalFiles, 0);
  const safeDirectories = results.filter(r => r.safe).length;
  const unsafeDirectories = results.filter(r => !r.safe).length;

  return {
    timestamp: new Date().toISOString(),
    directories: results,
    totalDirectories: results.length,
    totalFiles,
    totalThreats,
    totalWhitelisted,
    safeDirectories,
    unsafeDirectories,
    overallSafe: unsafeDirectories === 0,
  };
}

export function registerScanBatchCommand(
  program: Command,
  getOpts: () => ScanBatchCliOptions
): void {
  program
    .command('scan:batch')
    .description('Scan multiple directories from a list file')
    .option('--list-file <path>', 'Path to a file containing directory paths (one per line)')
    .option('--verbose', 'Show detailed threat information', false)
    .option('--log-level <level>', 'Logging verbosity (debug, info, warn, error)', 'info')
    .option('--whitelist-file <path>', 'Path to custom whitelist JSON file')
    .action(async (cmdOptions) => {
      const opts = getOpts();
      const verbose = opts.verbose || cmdOptions.verbose;
      const logLevel = (cmdOptions.logLevel || opts.logLevel) as LogLevel;
      const logger = createLogger(logLevel);

      if (!cmdOptions.listFile) {
        const error = { error: 'List file is required. Use --list-file <path>' };
        logger.error('scan:batch failed: no list file provided');
        formatOutput(error, opts.json);
        process.exit(1);
      }

      let directories: string[];
      try {
        directories = readDirectoryListFile(cmdOptions.listFile);
      } catch (err) {
        const error = { error: String(err) };
        logger.error('Failed to read list file', { error: String(err) });
        formatOutput(error, opts.json);
        process.exit(1);
      }

      if (directories.length === 0) {
        const error = { error: 'List file is empty or contains only comments' };
        logger.error('scan:batch failed: empty list file');
        formatOutput(error, opts.json);
        process.exit(1);
      }

      logger.info(`Starting batch scan of ${directories.length} directories`);

      let whitelist: WhitelistConfig | undefined;
      try {
        whitelist = loadWhitelist(cmdOptions.whitelistFile);
        if (whitelist.paths.length > 0 || whitelist.signatures.length > 0 || whitelist.extensions.length > 0) {
          logger.info('Loaded whitelist configuration', {
            paths: whitelist.paths.length,
            signatures: whitelist.signatures.length,
            extensions: whitelist.extensions.length,
          });
        }
      } catch (wlErr) {
        logger.warn('Failed to load whitelist configuration', { error: String(wlErr) });
      }

      const results: DirectoryResult[] = [];
      const errors: { path: string; error: string }[] = [];

      for (const dir of directories) {
        const normalizedPath = path.resolve(dir);

        if (!fs.existsSync(normalizedPath)) {
          errors.push({ path: normalizedPath, error: 'Path does not exist' });
          logger.warn(`Skipping non-existent path: ${normalizedPath}`);
          continue;
        }

        const stats = fs.statSync(normalizedPath);
        if (!stats.isDirectory()) {
          errors.push({ path: normalizedPath, error: 'Path is not a directory' });
          logger.warn(`Skipping non-directory path: ${normalizedPath}`);
          continue;
        }

        try {
          const result = scanSingleDirectory(
            normalizedPath,
            { verbose, dryRun: opts.dryRun },
            logger,
            whitelist
          );
          results.push(result);

          if (!opts.json) {
            const status = result.safe ? 'SAFE' : 'UNSAFE';
            console.log(`[${status}] ${normalizedPath} - ${result.threats.length} threat(s), ${result.totalFiles} files`);
          }
        } catch (err) {
          errors.push({ path: normalizedPath, error: String(err) });
          logger.error(`Failed to scan: ${normalizedPath}`, { error: String(err) });
        }
      }

      const report = buildBatchReport(results);

      if (!opts.json) {
        console.log(`\nBatch scan complete:`);
        console.log(`  Directories scanned: ${report.totalDirectories}`);
        console.log(`  Total files: ${report.totalFiles}`);
        console.log(`  Total threats: ${report.totalThreats}`);
        console.log(`  Safe directories: ${report.safeDirectories}`);
        console.log(`  Unsafe directories: ${report.unsafeDirectories}`);
        if (report.totalWhitelisted > 0) {
          console.log(`  Whitelisted: ${report.totalWhitelisted}`);
        }
        if (errors.length > 0) {
          console.log(`  Errors: ${errors.length}`);
          for (const e of errors) {
            console.log(`    - ${e.path}: ${e.error}`);
          }
        }
        console.log(`\nOverall result: ${report.overallSafe ? 'SAFE' : 'UNSAFE'}`);
      }

      const output = {
        ...report,
        errors: errors.length > 0 ? errors : undefined,
      };

      formatOutput(output, opts.json);

      if (!report.overallSafe) {
        process.exit(2);
      }
    });
}
