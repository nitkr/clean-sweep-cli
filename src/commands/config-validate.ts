import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import { execSync } from 'child_process';
import { detectWordPressRoot, formatWpPathError } from '../wp-path-detector';

export interface ConfigIssue {
  type: 'syntax_error' | 'insecure_config' | 'debug_enabled' | 'deprecated_constant' | 'weak_security';
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  line: number | null;
  constant: string | null;
  message: string;
  recommendation: string;
}

export interface ConfigValidateResult {
  path: string;
  exists: boolean;
  syntaxValid: boolean;
  debugEnabled: boolean;
  issues: ConfigIssue[];
  hasIssues: boolean;
  bySeverity: Record<string, number>;
}

const INSECURE_PATTERNS: Array<{
  pattern: RegExp;
  type: ConfigIssue['type'];
  severity: ConfigIssue['severity'];
  message: string;
  recommendation: string;
  extractConstant?: (match: RegExpMatchArray) => string | null;
}> = [
  {
    pattern: /define\s*\(\s*['"]AUTH_KEY['"]\s*,\s*['"]\s*['"]\s*\)/,
    type: 'insecure_config',
    severity: 'HIGH',
    message: 'AUTH_KEY is empty or uses a default value',
    recommendation: 'Set AUTH_KEY to a unique secret value',
    extractConstant: () => 'AUTH_KEY',
  },
  {
    pattern: /define\s*\(\s*['"]SECURE_AUTH_KEY['"]\s*,\s*['"]\s*['"]\s*\)/,
    type: 'insecure_config',
    severity: 'HIGH',
    message: 'SECURE_AUTH_KEY is empty or uses a default value',
    recommendation: 'Set SECURE_AUTH_KEY to a unique secret value',
    extractConstant: () => 'SECURE_AUTH_KEY',
  },
  {
    pattern: /define\s*\(\s*['"]LOGGED_IN_KEY['"]\s*,\s*['"]\s*['"]\s*\)/,
    type: 'insecure_config',
    severity: 'HIGH',
    message: 'LOGGED_IN_KEY is empty or uses a default value',
    recommendation: 'Set LOGGED_IN_KEY to a unique secret value',
    extractConstant: () => 'LOGGED_IN_KEY',
  },
  {
    pattern: /define\s*\(\s*['"]NONCE_KEY['"]\s*,\s*['"]\s*['"]\s*\)/,
    type: 'insecure_config',
    severity: 'HIGH',
    message: 'NONCE_KEY is empty or uses a default value',
    recommendation: 'Set NONCE_KEY to a unique secret value',
    extractConstant: () => 'NONCE_KEY',
  },
  {
    pattern: /define\s*\(\s*['"]AUTH_SALT['"]\s*,\s*['"]\s*['"]\s*\)/,
    type: 'insecure_config',
    severity: 'HIGH',
    message: 'AUTH_SALT is empty or uses a default value',
    recommendation: 'Set AUTH_SALT to a unique secret value',
    extractConstant: () => 'AUTH_SALT',
  },
  {
    pattern: /define\s*\(\s*['"]SECURE_AUTH_SALT['"]\s*,\s*['"]\s*['"]\s*\)/,
    type: 'insecure_config',
    severity: 'HIGH',
    message: 'SECURE_AUTH_SALT is empty or uses a default value',
    recommendation: 'Set SECURE_AUTH_SALT to a unique secret value',
    extractConstant: () => 'SECURE_AUTH_SALT',
  },
  {
    pattern: /define\s*\(\s*['"]LOGGED_IN_SALT['"]\s*,\s*['"]\s*['"]\s*\)/,
    type: 'insecure_config',
    severity: 'HIGH',
    message: 'LOGGED_IN_SALT is empty or uses a default value',
    recommendation: 'Set LOGGED_IN_SALT to a unique secret value',
    extractConstant: () => 'LOGGED_IN_SALT',
  },
  {
    pattern: /define\s*\(\s*['"]NONCE_SALT['"]\s*,\s*['"]\s*['"]\s*\)/,
    type: 'insecure_config',
    severity: 'HIGH',
    message: 'NONCE_SALT is empty or uses a default value',
    recommendation: 'Set NONCE_SALT to a unique secret value',
    extractConstant: () => 'NONCE_SALT',
  },
  {
    pattern: /\$table_prefix\s*=\s*['"]wp_['"]/,
    type: 'weak_security',
    severity: 'MEDIUM',
    message: 'Default table prefix "wp_" is used',
    recommendation: 'Change $table_prefix to a unique value to prevent SQL injection attacks',
    extractConstant: () => '$table_prefix',
  },
  {
    pattern: /define\s*\(\s*['"]DISALLOW_FILE_EDIT['"]\s*,\s*(?!true)/i,
    type: 'insecure_config',
    severity: 'MEDIUM',
    message: 'File editor is enabled in admin panel',
    recommendation: 'Set DISALLOW_FILE_EDIT to true to prevent code editing from the admin',
    extractConstant: () => 'DISALLOW_FILE_EDIT',
  },
  {
    pattern: /define\s*\(\s*['"]DISALLOW_FILE_MODS['"]\s*,\s*(?!true)/i,
    type: 'insecure_config',
    severity: 'LOW',
    message: 'File modifications are allowed from the admin',
    recommendation: 'Consider setting DISALLOW_FILE_MODS to true for production sites',
    extractConstant: () => 'DISALLOW_FILE_MODS',
  },
  {
    pattern: /define\s*\(\s*['"]FORCE_SSL_ADMIN['"]\s*,\s*(?!true)/i,
    type: 'weak_security',
    severity: 'MEDIUM',
    message: 'SSL is not enforced for admin area',
    recommendation: 'Set FORCE_SSL_ADMIN to true to enforce HTTPS for admin',
    extractConstant: () => 'FORCE_SSL_ADMIN',
  },
];

const DEBUG_PATTERNS: Array<{
  pattern: RegExp;
  type: ConfigIssue['type'];
  severity: ConfigIssue['severity'];
  message: string;
  recommendation: string;
  extractConstant: (match: RegExpMatchArray) => string | null;
}> = [
  {
    pattern: /define\s*\(\s*['"]WP_DEBUG['"]\s*,\s*true\s*\)/i,
    type: 'debug_enabled',
    severity: 'MEDIUM',
    message: 'WP_DEBUG is enabled',
    recommendation: 'Set WP_DEBUG to false for production environments',
    extractConstant: () => 'WP_DEBUG',
  },
  {
    pattern: /define\s*\(\s*['"]WP_DEBUG_LOG['"]\s*,\s*true\s*\)/i,
    type: 'debug_enabled',
    severity: 'LOW',
    message: 'WP_DEBUG_LOG is enabled',
    recommendation: 'Set WP_DEBUG_LOG to false for production to avoid exposing debug information',
    extractConstant: () => 'WP_DEBUG_LOG',
  },
  {
    pattern: /define\s*\(\s*['"]WP_DEBUG_DISPLAY['"]\s*,\s*true\s*\)/i,
    type: 'debug_enabled',
    severity: 'HIGH',
    message: 'WP_DEBUG_DISPLAY is enabled - errors are shown to users',
    recommendation: 'Set WP_DEBUG_DISPLAY to false to prevent exposing errors to visitors',
    extractConstant: () => 'WP_DEBUG_DISPLAY',
  },
  {
    pattern: /define\s*\(\s*['"]SCRIPT_DEBUG['"]\s*,\s*true\s*\)/i,
    type: 'debug_enabled',
    severity: 'LOW',
    message: 'SCRIPT_DEBUG is enabled',
    recommendation: 'Set SCRIPT_DEBUG to false for production to load minified assets',
    extractConstant: () => 'SCRIPT_DEBUG',
  },
];

function getLineNumber(content: string, pattern: RegExp): number | null {
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (pattern.test(lines[i])) {
      return i + 1;
    }
  }
  return null;
}

export function validateConfigSyntax(filePath: string): { valid: boolean; error: string | null; phpAvailable: boolean } {
  try {
    execSync('php --version', { stdio: 'pipe', timeout: 5000 });
  } catch {
    return { valid: true, error: null, phpAvailable: false };
  }

  try {
    execSync(`php -l "${filePath}"`, { stdio: 'pipe', timeout: 10000 });
    return { valid: true, error: null, phpAvailable: true };
  } catch (err) {
    const errorOutput = (err as Error & { stderr?: Buffer }).stderr?.toString() || '';
    const match = errorOutput.match(/Parse error.*line\s+(\d+)/i);
    return {
      valid: false,
      error: match ? `Parse error on line ${match[1]}` : 'PHP syntax error detected',
      phpAvailable: true,
    };
  }
}

export function validateConfig(configPath: string): ConfigValidateResult {
  const resolvedPath = path.resolve(configPath);

  if (!fs.existsSync(resolvedPath)) {
    return {
      path: resolvedPath,
      exists: false,
      syntaxValid: false,
      debugEnabled: false,
      issues: [],
      hasIssues: false,
      bySeverity: {},
    };
  }

  const content = fs.readFileSync(resolvedPath, 'utf-8');
  const issues: ConfigIssue[] = [];

  const syntax = validateConfigSyntax(resolvedPath);
  if (!syntax.valid && syntax.phpAvailable) {
    issues.push({
      type: 'syntax_error',
      severity: 'HIGH',
      line: null,
      constant: null,
      message: syntax.error || 'PHP syntax error detected',
      recommendation: 'Fix the PHP syntax error in wp-config.php',
    });
  }

  for (const entry of INSECURE_PATTERNS) {
    const match = content.match(entry.pattern);
    if (match) {
      const line = getLineNumber(content, entry.pattern);
      issues.push({
        type: entry.type,
        severity: entry.severity,
        line,
        constant: entry.extractConstant ? entry.extractConstant(match) : null,
        message: entry.message,
        recommendation: entry.recommendation,
      });
    }
  }

  let debugEnabled = false;
  for (const entry of DEBUG_PATTERNS) {
    const match = content.match(entry.pattern);
    if (match) {
      debugEnabled = true;
      const line = getLineNumber(content, entry.pattern);
      issues.push({
        type: entry.type,
        severity: entry.severity,
        line,
        constant: entry.extractConstant(match),
        message: entry.message,
        recommendation: entry.recommendation,
      });
    }
  }

  const bySeverity: Record<string, number> = {};
  for (const issue of issues) {
    bySeverity[issue.severity] = (bySeverity[issue.severity] || 0) + 1;
  }

  return {
    path: resolvedPath,
    exists: true,
    syntaxValid: syntax.valid,
    debugEnabled,
    issues,
    hasIssues: issues.length > 0,
    bySeverity,
  };
}

export function registerConfigValidateCommand(
  program: Command,
  getOpts: () => {
    dryRun: boolean;
    force: boolean;
    json: boolean;
    path: string;
    verbose: boolean;
    logLevel: string;
  }
): void {
  program
    .command('config:validate')
    .description('Validate WordPress wp-config.php for syntax and security issues')
    .option('--path <path>', 'Path to wp-config.php or its containing directory')
    .option('--json', 'Output results as JSON', false)
    .option('--config-file <file>', 'Explicit path to wp-config.php')
    .action((cmdOptions) => {
      const opts = getOpts();
      const useJson = cmdOptions.json || opts.json;
      let targetPath: string;

      if (cmdOptions.configFile) {
        targetPath = path.resolve(cmdOptions.configFile);
      } else {
        let basePath = path.resolve(cmdOptions.path || opts.path);
        const wpResult = detectWordPressRoot(basePath);
        if (!wpResult.found) {
          const error = { error: formatWpPathError(wpResult, 'config:validate'), path: basePath };
          if (useJson) {
            console.log(JSON.stringify(error, null, 2));
          } else {
            console.error(`Error: ${error.error}`);
          }
          process.exit(1);
        }
        basePath = wpResult.path;
        targetPath = path.join(basePath, 'wp-config.php');
      }

      if (!fs.existsSync(targetPath)) {
        const error = { error: 'wp-config.php not found', path: targetPath };
        if (useJson) {
          console.log(JSON.stringify(error, null, 2));
        } else {
          console.error(`Error: wp-config.php not found at: ${targetPath}`);
        }
        process.exit(1);
      }

      if (!useJson) {
        console.log(`Validating WordPress configuration: ${targetPath}`);
      }

      const result = validateConfig(targetPath);

      if (useJson) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.log(`\nSyntax: ${result.syntaxValid ? 'VALID' : 'INVALID'}`);
        console.log(`Debug mode: ${result.debugEnabled ? 'ENABLED' : 'DISABLED'}`);

        if (result.issues.length === 0) {
          console.log('\nNo configuration issues found.');
        } else {
          console.log(`\nFound ${result.issues.length} issue(s):`);

          for (const issue of result.issues) {
            const lineInfo = issue.line ? ` (line ${issue.line})` : '';
            console.log(`  [${issue.severity}] ${issue.constant || 'General'}${lineInfo}`);
            console.log(`    ${issue.message}`);
            console.log(`    Recommendation: ${issue.recommendation}`);
          }

          console.log('\nSeverity breakdown:');
          for (const sev of ['HIGH', 'MEDIUM', 'LOW']) {
            const count = result.bySeverity[sev] || 0;
            if (count > 0) {
              console.log(`  ${sev}: ${count}`);
            }
          }
        }
      }

      process.exit(result.hasIssues ? 1 : 0);
    });
}
