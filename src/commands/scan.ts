import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import fg from 'fast-glob';
import { detectThreats, ScanResult } from '../malware-scanner';
import { scanVulnerabilities, Vulnerability } from '../vulnerability-scanner';
import { checkWordPressIntegrity, IntegrityResult } from '../file-integrity';
import { createLogger, getLogger, LogLevel, generateReport, saveReport, getDefaultReportPath } from '../logger';

interface CliOptions {
  dryRun: boolean;
  force: boolean;
  json: boolean;
  path: string;
  verbose: boolean;
  checkVulnerabilities: boolean;
  checkIntegrity: boolean;
  report: boolean;
  logLevel: string;
}

function formatOutput(data: unknown, useJson: boolean): void {
  if (useJson) {
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(data);
  }
}

function buildSuggestions(
  threats: ScanResult['threats'],
  vulnerabilities: Vulnerability[],
  integrity?: IntegrityResult
): string[] {
  const suggestions: string[] = [];

  if (threats.length > 0) {
    const hasMalware = threats.some(t =>
      t.type.startsWith('php_') || t.type.startsWith('js_')
    );
    if (hasMalware) {
      suggestions.push('Consider removing suspicious files or restoring from backup');
    }
  }

  if (vulnerabilities.length > 0) {
    suggestions.push('Update affected components to latest versions');
  }

  if (integrity && integrity.modified > 0) {
    suggestions.push("Run 'clean-sweep core:repair' to restore core files");
  }

  return suggestions;
}

async function scanDirectory(
  targetPath: string,
  options: { verbose: boolean; dryRun: boolean },
  logger: ReturnType<typeof createLogger>
): Promise<ScanResult> {
  const ignore = ['**/node_modules/**', '**/dist/**', '**/.git/**'];
  const [files, directories] = await Promise.all([
    fg('**/*', { cwd: targetPath, absolute: true, onlyFiles: true, ignore }),
    fg('**/*', { cwd: targetPath, absolute: true, onlyDirectories: true, ignore }),
  ]);

  const threats: ReturnType<typeof detectThreats> = [];
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
    .option('--path <path>', 'Directory to scan')
    .option('--verbose', 'Show detailed threat information', false)
    .option('--check-vulnerabilities', 'Check for known WordPress vulnerabilities', false)
    .option('--check-integrity', 'Check WordPress core file integrity', false)
    .option('--report', 'Save JSON report to file', false)
    .option('--log-level <level>', 'Logging verbosity (debug, info, warn, error)', 'info')
    .action(async (cmdOptions) => {
      const opts = getOpts();
      const targetPath = cmdOptions.path || opts.path;
      const verbose = opts.verbose || cmdOptions.verbose;
      const report = cmdOptions.report ?? opts.report;
      const logLevel = (cmdOptions.logLevel || opts.logLevel) as LogLevel;

      const logger = createLogger(logLevel);
      logger.info(`Starting scan of directory: ${targetPath}`, { logLevel });

      const normalizedPath = path.resolve(targetPath);

      if (!fs.existsSync(normalizedPath)) {
        const error = { error: 'Path does not exist', path: normalizedPath };
        logger.error('Scan failed: path does not exist', { path: normalizedPath });
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      }

      const stats = fs.statSync(normalizedPath);
      if (!stats.isDirectory()) {
        const error = { error: 'Path is not a directory', path: normalizedPath };
        logger.error('Scan failed: path is not a directory', { path: normalizedPath });
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      }

      try {
        const result = await scanDirectory(normalizedPath, {
          verbose,
          dryRun: opts.dryRun,
        }, logger);

        const checkVulns = opts.checkVulnerabilities || cmdOptions.checkVulnerabilities;
        const checkIntegrity = opts.checkIntegrity || cmdOptions.checkIntegrity;
        let vulnerabilities: Vulnerability[] = [];
        let integrity: IntegrityResult | undefined;

        if (checkVulns) {
          logger.info('Checking for vulnerabilities...');
          console.log('Checking for vulnerabilities...');
          const vulnResult = await scanVulnerabilities(normalizedPath);
          vulnerabilities = vulnResult.vulnerabilities;

          if (!opts.json && !cmdOptions.json) {
            if (vulnResult.wordpress) {
              console.log(`  WordPress: ${vulnResult.wordpress}`);
            }
            if (vulnResult.plugins.length > 0) {
              console.log(`  Plugins: ${vulnResult.plugins.length} found`);
            }
          }
        }

        if (checkIntegrity) {
          logger.info('Checking core file integrity...');
          console.log('Checking core file integrity...');
          integrity = await checkWordPressIntegrity(normalizedPath);

          if (!opts.json && !cmdOptions.json) {
            if (integrity.wordpressVersion) {
              console.log(`  WordPress version: ${integrity.wordpressVersion}`);
            }
            console.log(`  Files checked: ${integrity.checked}`);
            console.log(`  Modified files: ${integrity.modified}`);
            if (integrity.modifiedFiles.length > 0) {
              console.log('  Modified core files:');
              for (const file of integrity.modifiedFiles) {
                console.log(`    - ${file}`);
              }
            }
          }
        }

        const suggestions = buildSuggestions(result.threats, vulnerabilities, integrity);

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

        if (!opts.json && !cmdOptions.json && vulnerabilities.length > 0) {
          console.log(`\nFound ${vulnerabilities.length} known vulnerability(ies):`);
          for (const vuln of vulnerabilities) {
            console.log(`  - [${vuln.severity}] ${vuln.component} ${vuln.version}: ${vuln.title} (${vuln.cve})`);
          }
        }

        if (!opts.json && !cmdOptions.json && suggestions.length > 0) {
          console.log('\nSuggestions:');
          for (const suggestion of suggestions) {
            console.log(`  - ${suggestion}`);
          }
        }

        const output = {
          ...result,
          ...(checkVulns && { vulnerabilities }),
          ...(checkIntegrity && { integrity }),
          suggestions,
        };

        if (report) {
          const reportData = generateReport(normalizedPath, output, suggestions);
          const reportPath = getDefaultReportPath(normalizedPath);
          saveReport(reportData, reportPath);
          console.log(`\nReport saved to: ${reportPath}`);
          logger.info('Report saved', { reportPath });
        }

        if (result.safe) {
          logger.info('Scan completed successfully - no threats found');
        } else {
          logger.warn(`Scan completed - found ${result.threats.length} threat(s)`);
        }

        formatOutput(output, opts.json || cmdOptions.json);
      } catch (err) {
        const error = { error: 'Scan failed', message: String(err) };
        logger.error('Scan failed with error', { error: String(err) });
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      }
    });
}
