import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import fg from 'fast-glob';
import { detectThreats, ScanResult } from '../malware-scanner';
import { scanVulnerabilities, Vulnerability } from '../vulnerability-scanner';
import { checkWordPressIntegrity, IntegrityResult } from '../file-integrity';
import { findUnknownFiles, UnknownFilesResult } from '../wp-file-detector';
import { createLogger, getLogger, LogLevel, generateReport, saveReport, getDefaultReportPath } from '../logger';
import { generateHtmlReport, saveHtmlReport, getDefaultHtmlReportPath, HtmlReportData } from '../html-report';
import { loadWhitelist, applyWhitelist, WhitelistConfig } from '../whitelist';
import { detectWordPressRoot, formatWpPathError } from '../wp-path-detector';
import { severityColor, severityIcon, icons, createTable, createVulnerabilityTable, createThreatTable } from '../output';

interface CliOptions {
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
  logger: ReturnType<typeof createLogger>,
  whitelist?: WhitelistConfig
): Promise<ScanResult> {
  const ignore = ['**/node_modules/**', '**/vendor/**', '**/dist/**', '**/.git/**'];
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

  const totalBeforeWhitelist = threats.length;
  let filteredThreats = threats;
  let whitelistedCount = 0;

  if (whitelist) {
    const { applyWhitelist: applyWhitelistFn } = require('../whitelist');
    filteredThreats = applyWhitelistFn(threats, whitelist);
    whitelistedCount = totalBeforeWhitelist - filteredThreats.length;
    if (whitelistedCount > 0) {
      console.log(`Whitelist filtered out ${whitelistedCount} threat(s)`);
    }
  }

  return {
    path: targetPath,
    files,
    directories,
    totalFiles: files.length,
    totalDirectories: directories.length,
    threats: filteredThreats,
    safe: filteredThreats.length === 0,
    dryRun: options.dryRun,
    whitelisted: whitelistedCount,
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
    .option('--find-unknown', 'Find unknown files not part of WordPress core', false)
    .option('--report', 'Save JSON report to file', false)
    .option('--html-report', 'Save HTML report to file', false)
    .option('--log-level <level>', 'Logging verbosity (debug, info, warn, error)', 'info')
    .option('--whitelist-file <path>', 'Path to custom whitelist JSON file')
    .action(async (cmdOptions) => {
      const opts = getOpts();
      let targetPath = cmdOptions.path || opts.path;
      const verbose = opts.verbose || cmdOptions.verbose;

      if (!cmdOptions.path && opts.path === process.cwd()) {
        const wpResult = detectWordPressRoot(targetPath);
        if (wpResult.found) {
          targetPath = wpResult.path;
        }
      }
      const report = cmdOptions.report || opts.report;
      const htmlReport = cmdOptions.htmlReport || opts.htmlReport;
      const logLevel = (cmdOptions.logLevel || opts.logLevel) as LogLevel;

      const logger = createLogger(logLevel);
      const useJson = opts.json || cmdOptions.json;
      if (useJson) {
        logger.setSilent(true);
      }
      if (!useJson) {
        console.log(`${icons.scanning} Starting scan of directory: ${targetPath}`);
      }

      const normalizedPath = path.resolve(targetPath);

      if (!fs.existsSync(normalizedPath)) {
        const error = { error: 'Path does not exist', path: normalizedPath };
        logger.error('Scan failed: path does not exist', { path: normalizedPath });
        formatOutput(error, useJson);
        process.exit(1);
      }

      const stats = fs.statSync(normalizedPath);
      if (!stats.isDirectory()) {
        const error = { error: 'Path is not a directory', path: normalizedPath };
        logger.error('Scan failed: path is not a directory', { path: normalizedPath });
        formatOutput(error, useJson);
        process.exit(1);
      }

      try {
        const whitelistFile = cmdOptions.whitelistFile;
        let whitelist: WhitelistConfig | undefined;
        try {
          whitelist = loadWhitelist(whitelistFile);
          if (whitelist.paths.length > 0 || whitelist.signatures.length > 0 || whitelist.extensions.length > 0) {
            if (!useJson) {
              console.log('Loaded whitelist configuration', {
                paths: whitelist.paths.length,
                signatures: whitelist.signatures.length,
                extensions: whitelist.extensions.length,
              });
            }
          }
        } catch (wlErr) {
          logger.warn('Failed to load whitelist configuration', { error: String(wlErr) });
        }

        const result = await scanDirectory(normalizedPath, {
          verbose,
          dryRun: opts.dryRun,
        }, logger, whitelist);

        const checkVulns = opts.checkVulnerabilities || cmdOptions.checkVulnerabilities;
        const checkIntegrity = opts.checkIntegrity || cmdOptions.checkIntegrity;
        const findUnknown = opts.findUnknown || cmdOptions.findUnknown;
        let vulnerabilities: Vulnerability[] = [];
        let integrity: IntegrityResult | undefined;
        let unknownFiles: UnknownFilesResult | undefined;

        if (checkVulns) {
          const vulnResult = await scanVulnerabilities(normalizedPath);
          vulnerabilities = vulnResult.vulnerabilities;

          if (!useJson) {
            console.log('Checking for vulnerabilities...');
            if (vulnResult.wordpress) {
              console.log(`  WordPress: ${vulnResult.wordpress}`);
            }
            if (vulnResult.plugins.length > 0) {
              console.log(`  Plugins: ${vulnResult.plugins.length} found`);
            }
          }
        }

        if (checkIntegrity) {
          integrity = await checkWordPressIntegrity(normalizedPath);

          if (!useJson) {
            console.log('Checking core file integrity...');
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

        if (findUnknown) {
          unknownFiles = await findUnknownFiles(normalizedPath);

          if (!useJson) {
            console.log('Finding unknown files...');
            console.log(`  Unknown files found: ${unknownFiles.count}`);
            if (unknownFiles.files.length > 0 && unknownFiles.files.length <= 20) {
              console.log('  Unknown files:');
              for (const file of unknownFiles.files) {
                console.log(`    - ${file}`);
              }
            } else if (unknownFiles.files.length > 20) {
              console.log('  (Showing first 20 files)');
              for (const file of unknownFiles.files.slice(0, 20)) {
                console.log(`    - ${file}`);
              }
            }
          }
        }

        const suggestions = buildSuggestions(result.threats, vulnerabilities, integrity);

        if (!useJson) {
          if (result.threats.length > 0) {
            console.log(`\n${icons.error} ${severityColor('critical')('UNSAFE')} – Issues found\n`);
            
            const threatTable = createThreatTable() as any;
            for (const threat of result.threats) {
              const lineInfo = threat.line !== null ? `:${threat.line}` : '';
              const sev = (threat as any).severity || 'medium';
              threatTable.push([
                threat.file + lineInfo,
                threat.type,
                `${severityIcon(sev)} ${severityColor(sev)(sev.toUpperCase())}`
              ]);
            }
            console.log(threatTable.toString());
            
            if (result.whitelisted > 0) {
              console.log(`\nFiltered out ${result.whitelisted} whitelisted threat(s)`);
            }
          } else {
            console.log(`\n${icons.safe} ${severityColor('info')('SAFE')} – No threats found (safe)`);
          }
        }

        if (!useJson && vulnerabilities.length > 0) {
          console.log(`\nVULNERABILITIES (${vulnerabilities.length})\n`);
          
          const vulnTable = createVulnerabilityTable() as any;
          for (const vuln of vulnerabilities) {
            const sev = vuln.severity || 'medium';
            vulnTable.push([
              vuln.component,
              vuln.version || 'unknown',
              vuln.title,
              vuln.cve || 'N/A',
              `${severityIcon(sev)} ${severityColor(sev)(sev.toUpperCase())}`,
              (vuln as any).recommendation || 'Update plugin'
            ]);
          }
          console.log(vulnTable.toString());
        }

        if (!useJson && suggestions.length > 0) {
          console.log('\nSuggestions:');
          for (const suggestion of suggestions) {
            console.log(`  - ${suggestion}`);
          }
        }

        const output = {
          ...result,
          ...(checkVulns && { vulnerabilities }),
          ...(checkIntegrity && { integrity }),
          ...(findUnknown && { unknownFiles }),
          suggestions,
        };

        if (report) {
          const reportData = generateReport(normalizedPath, output, suggestions);
          const reportPath = getDefaultReportPath(normalizedPath);
          saveReport(reportData, reportPath);
          if (!useJson) {
            console.log(`\nReport saved to: ${reportPath}`);
          }
          logger.info('Report saved', { reportPath });
        }

        if (htmlReport) {
          const htmlReportData: HtmlReportData = {
            timestamp: new Date().toISOString(),
            scanPath: normalizedPath,
            scanResult: result,
            ...(checkVulns && { vulnerabilities }),
            ...(checkIntegrity && { integrity }),
            suggestions,
          };
          const html = generateHtmlReport(htmlReportData);
          const htmlReportPath = getDefaultHtmlReportPath(normalizedPath);
          saveHtmlReport(html, htmlReportPath);
          if (!useJson) {
            console.log(`\nHTML report saved to: ${htmlReportPath}`);
          }
          logger.info('HTML report saved', { htmlReportPath });
        }

        if (!useJson) {
          if (result.safe) {
            console.log(`\n${icons.safe} Scan completed successfully - no threats found`);
          } else {
            console.log(`\n${icons.error} Scan completed - found ${result.threats.length} threat(s)`);
          }
        }

        if (useJson) {
          formatOutput(output, useJson);
        }
      } catch (err) {
        const error = { error: 'Scan failed', message: String(err) };
        logger.error('Scan failed with error', { error: String(err) });
        formatOutput(error, useJson);
        process.exit(1);
      }
    });
}
