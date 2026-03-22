#!/usr/bin/env node

import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import fg from 'fast-glob';
import winston from 'winston';

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

interface Threat {
  file: string;
  type: string;
  line: number | null;
  signature: string;
}

interface ScanResult {
  path: string;
  files: string[];
  directories: string[];
  totalFiles: number;
  totalDirectories: number;
  threats: Threat[];
  safe: boolean;
  dryRun: boolean;
}

const MALICIOUS_PATTERNS = {
  phpFunctions: [
    { pattern: /eval\s*\(/gi, type: 'php_eval' },
    { pattern: /base64_decode\s*\(/gi, type: 'php_base64_decode' },
    { pattern: /shell_exec\s*\(/gi, type: 'php_shell_exec' },
    { pattern: /system\s*\(/gi, type: 'php_system' },
    { pattern: /passthru\s*\(/gi, type: 'php_passthru' },
    { pattern: /exec\s*\(/gi, type: 'php_exec' },
    { pattern: /proc_open\s*\(/gi, type: 'php_proc_open' },
    { pattern: /popen\s*\(/gi, type: 'php_popen' },
    { pattern: /curl_exec\s*\(/gi, type: 'php_curl_exec' },
    { pattern: /assert\s*\(/gi, type: 'php_assert' },
    { pattern: /preg_replace.*\/e/gi, type: 'php_preg_replace_eval' },
    { pattern: /create_function\s*\(/gi, type: 'php_create_function' },
    { pattern: /call_user_func\s*\(/gi, type: 'php_call_user_func' },
    { pattern: /\$_GET\s*\[/gi, type: 'php_get_parameter' },
    { pattern: /\$_POST\s*\(/gi, type: 'php_post_parameter' },
    { pattern: /\$_REQUEST\s*\(/gi, type: 'php_request_parameter' },
    { pattern: /gzinflate\s*\(/gi, type: 'php_gzinflate' },
    { pattern: /gzuncompress\s*\(/gi, type: 'php_gzuncompress' },
    { pattern: /str_rot13\s*\(/gi, type: 'php_str_rot13' },
  ],
  jsPatterns: [
    { pattern: /eval\s*\(\s*['"`]/gi, type: 'js_eval_dynamic' },
    { pattern: /Function\s*\(\s*['"`]/gi, type: 'js_function_dynamic' },
    { pattern: /setTimeout\s*\(\s*['"`]/gi, type: 'js_settimeout_dynamic' },
    { pattern: /setInterval\s*\(\s*['"`]/gi, type: 'js_setinterval_dynamic' },
    { pattern: /document\.write\s*\(/gi, type: 'js_document_write' },
    { pattern: /window\.\[\s*['"`]/gi, type: 'js_dynamic_property' },
    { pattern: /child_process.*exec\s*\(/gi, type: 'js_child_process_exec' },
    { pattern: /child_process.*spawn\s*\(/gi, type: 'js_child_process_spawn' },
    { pattern: /require\s*\(\s*process/gi, type: 'js_process_require' },
    { pattern: /process\.binding\s*\(/gi, type: 'js_process_binding' },
  ],
  suspiciousFilePatterns: [
    { pattern: /\.php\d+$/i, type: 'suspicious_php_extension' },
    { pattern: /^[a-zA-Z0-9_-]+\.php$/i, type: 'suspicious_php_filename' },
    { pattern: /\.(phtml|php3|php4|php5|phar)$/i, type: 'alternative_php' },
    { pattern: /^[\.\/\\]*\.\./gi, type: 'path_traversal' },
  ],
  encodedContent: [
    { pattern: /^[a-zA-Z0-9+\/=]{100,}$/gm, type: 'base64_large' },
    { pattern: /chr\s*\(\s*\d+\s*\)\s*\.\s*chr/gi, type: 'char_encoding' },
    { pattern: /\\\\x[0-9a-f]{2}/gi, type: 'hex_escape' },
  ],
};

function detectThreats(filePath: string, content: string, verbose: boolean): Threat[] {
  const threats: Threat[] = [];
  const ext = path.extname(filePath).toLowerCase();
  const lines = content.split('\n');

  const patternsToCheck = [
    ...(ext === '.php' ? MALICIOUS_PATTERNS.phpFunctions : []),
    ...(ext === '.js' ? MALICIOUS_PATTERNS.jsPatterns : []),
    ...MALICIOUS_PATTERNS.suspiciousFilePatterns,
    ...MALICIOUS_PATTERNS.encodedContent,
  ];

  for (const { pattern, type } of patternsToCheck) {
    const regex = new RegExp(pattern.source, pattern.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(content)) !== null) {
      let line: number | null = null;

      if (verbose) {
        const position = content.substring(0, match.index).split('\n').length;
        line = position;
      }

      threats.push({
        file: filePath,
        type,
        line,
        signature: match[0].substring(0, 100),
      });

      if (!verbose) break;
    }
  }

  return threats;
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

  const threats: Threat[] = [];
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

function formatOutput(data: unknown, useJson: boolean): void {
  if (useJson) {
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(data);
  }
}

const program = new Command();

program
  .name('clean-sweep')
  .description('CLI tool for cleaning and managing project files')
  .version('1.0.0')
  .option('--dry-run', 'Preview changes without applying them', true)
  .option('--force', 'Skip confirmation prompts', false)
  .option('--json', 'Output results as JSON', false)
  .option('--path <path>', 'Target path to operate on', process.cwd())
  .option('--verbose', 'Show detailed threat information', false);

program
  .command('scan')
  .description('Scan directory for files and directories')
  .option('--path <path>', 'Directory to scan', program.opts().path)
  .option('--verbose', 'Show detailed threat information', false)
  .action(async (cmdOptions) => {
    const opts = program.opts() as CliOptions;
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

program.parse(process.argv);

if (!process.argv.slice(2).length) {
  program.outputHelp();
}
