import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import fg from 'fast-glob';
import winston from 'winston';
import { detectThreats, ScanResult } from '../malware-scanner';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.Console()],
});

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

async function scanDirectory(
  targetPath: string,
  options: { verbose: boolean; dryRun: boolean }
): Promise<ScanResult> {
  const ignore = ['**/node_modules/**', '**/dist/**', '**/.git/**'];
  const [files, directories] = await Promise.all([
    fg('**/*', { cwd: targetPath, absolute: true, onlyFiles: true, ignore }),
    fg('**/*', { cwd: targetPath, absolute: true, onlyDirectories: true, ignore }),
  ]);

  const threats: ReturnType<typeof detectThreats> = [];
  const scanExtensions = ['.php', '.js'];

  for (const file of files) {
    const ext = path.extname(file).toLowerCase();
    if (!scanExtensions.includes(ext)) continue;

    try {
      const content = fs.readFileSync(file, 'utf-8');
      const fileThreats = detectThreats(file, content, options.verbose);
      threats.push(...fileThreats);
    } catch {
      // Skip files that can't be read
    }
  }

  return {
    path: targetPath,
    files,
    directories,
    totalFiles: files.length,
    totalDirectories: directories.length,
    threats,
    safe: threats.length === 0,
    dryRun: options.dryRun,
  };
}

export function registerScanCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  program
    .command('scan')
    .description('Scan directory for files and directories')
    .option('--path <path>', 'Directory to scan', getOpts().path)
    .option('--verbose', 'Show detailed threat information', false)
    .action(async (cmdOptions) => {
      const opts = getOpts();
      const targetPath = cmdOptions.path || opts.path;
      const verbose = opts.verbose || cmdOptions.verbose;

      logger.info(`Scanning directory: ${targetPath}`);

      const normalizedPath = path.resolve(targetPath);

      if (!fs.existsSync(normalizedPath)) {
        const error = { error: 'Path does not exist', path: normalizedPath };
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      }

      const stats = fs.statSync(normalizedPath);
      if (!stats.isDirectory()) {
        const error = { error: 'Path is not a directory', path: normalizedPath };
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      }

      try {
        const result = await scanDirectory(normalizedPath, {
          verbose,
          dryRun: opts.dryRun,
        });

        if (!opts.json && !cmdOptions.json && result.threats.length > 0) {
          console.log(`\nFound ${result.threats.length} potential threat(s):`);
          for (const threat of result.threats) {
            const lineInfo = threat.line !== null ? `:${threat.line}` : '';
            console.log(`  - ${threat.file}${lineInfo} [${threat.type}]`);
            if (verbose) {
              console.log(`    Signature: ${threat.signature}`);
            }
          }
          console.log(`\nScan result: ${result.safe ? 'SAFE' : 'UNSAFE'}`);
        }

        formatOutput(result, opts.json || cmdOptions.json);
      } catch (err) {
        const error = { error: 'Scan failed', message: String(err) };
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      }
    });
}
