import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { Command } from 'commander';

import { registerConfigValidateCommand, validateConfig, ConfigIssue } from '../src/commands/config-validate';

function createTestCliOptions(
  overrides: Partial<{
    dryRun: boolean;
    force: boolean;
    json: boolean;
    path: string;
    verbose: boolean;
    logLevel: string;
  }> = {}
) {
  return () => ({
    dryRun: true,
    force: false,
    json: false,
    path: process.cwd(),
    verbose: false,
    logLevel: 'error' as string,
    checkVulnerabilities: false,
    checkIntegrity: false,
    findUnknown: false,
    report: false,
    ...overrides,
  });
}

function createProgram() {
  const program = new Command();
  program.exitOverride();
  return program;
}

function makeSecureConfig(): string {
  return `<?php
define('DB_NAME', 'wordpress');
define('DB_USER', 'wpuser');
define('DB_PASSWORD', 'securepass123');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8');
define('DB_COLLATE', '');

define('AUTH_KEY',         'unique-random-string-1');
define('SECURE_AUTH_KEY',  'unique-random-string-2');
define('LOGGED_IN_KEY',    'unique-random-string-3');
define('NONCE_KEY',        'unique-random-string-4');
define('AUTH_SALT',        'unique-random-string-5');
define('SECURE_AUTH_SALT', 'unique-random-string-6');
define('LOGGED_IN_SALT',   'unique-random-string-7');
define('NONCE_SALT',       'unique-random-string-8');

$table_prefix = 'xk9_';

define('WP_DEBUG', false);
define('WP_DEBUG_LOG', false);
define('WP_DEBUG_DISPLAY', false);

if ( ! defined( 'ABSPATH' ) ) {
  define( 'ABSPATH', __DIR__ . '/' );
}

require_once ABSPATH . 'wp-settings.php';
`;
}

function makeInsecureConfig(): string {
  return `<?php
define('DB_NAME', 'wordpress');
define('DB_USER', 'admin');
define('DB_PASSWORD', 'password');
define('DB_HOST', 'localhost');

define('AUTH_KEY',         '');
define('SECURE_AUTH_KEY',  '');
define('LOGGED_IN_KEY',    '');
define('NONCE_KEY',        '');
define('AUTH_SALT',        '');
define('SECURE_AUTH_SALT', '');
define('LOGGED_IN_SALT',   '');
define('NONCE_SALT',       '');

$table_prefix = 'wp_';

define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
define('WP_DEBUG_DISPLAY', true);
define('SCRIPT_DEBUG', true);

if ( ! defined( 'ABSPATH' ) ) {
  define( 'ABSPATH', __DIR__ . '/' );
}

require_once ABSPATH . 'wp-settings.php';
`;
}

function makeDebugOnlyConfig(): string {
  return `<?php
define('DB_NAME', 'wordpress');
define('DB_USER', 'wpuser');
define('DB_PASSWORD', 'securepass123');
define('DB_HOST', 'localhost');

define('AUTH_KEY',         'unique-key-1');
define('SECURE_AUTH_KEY',  'unique-key-2');
define('LOGGED_IN_KEY',    'unique-key-3');
define('NONCE_KEY',        'unique-key-4');
define('AUTH_SALT',        'unique-salt-1');
define('SECURE_AUTH_SALT', 'unique-salt-2');
define('LOGGED_IN_SALT',   'unique-salt-3');
define('NONCE_SALT',       'unique-salt-4');

$table_prefix = 'xk9_';

define('WP_DEBUG', true);
define('WP_DEBUG_DISPLAY', false);
define('WP_DEBUG_LOG', false);

if ( ! defined( 'ABSPATH' ) ) {
  define( 'ABSPATH', __DIR__ . '/' );
}

require_once ABSPATH . 'wp-settings.php';
`;
}

describe('Config Validate Command', () => {
  let tempDir: string;
  let consoleSpy: ReturnType<typeof jest.spyOn>;
  let consoleErrorSpy: ReturnType<typeof jest.spyOn>;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'config-validate-test-'));
    consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
    consoleSpy.mockRestore();
    consoleErrorSpy.mockRestore();
  });

  describe('validateConfig function', () => {
    it('should return exists=false for missing file', () => {
      const result = validateConfig(path.join(tempDir, 'wp-config.php'));
      expect(result.exists).toBe(false);
      expect(result.hasIssues).toBe(false);
    });

    it('should return no issues for a secure config', () => {
      const configPath = path.join(tempDir, 'wp-config.php');
      fs.writeFileSync(configPath, makeSecureConfig());

      const result = validateConfig(configPath);

      expect(result.exists).toBe(true);
      expect(result.hasIssues).toBe(false);
      expect(result.issues).toHaveLength(0);
      expect(result.debugEnabled).toBe(false);
    });

    it('should detect empty auth keys', () => {
      const configPath = path.join(tempDir, 'wp-config.php');
      fs.writeFileSync(configPath, makeInsecureConfig());

      const result = validateConfig(configPath);

      expect(result.hasIssues).toBe(true);

      const authKeyIssues = result.issues.filter(
        i => i.constant === 'AUTH_KEY' && i.type === 'insecure_config'
      );
      expect(authKeyIssues.length).toBeGreaterThan(0);
      expect(authKeyIssues[0].severity).toBe('HIGH');
    });

    it('should detect empty salt values', () => {
      const configPath = path.join(tempDir, 'wp-config.php');
      fs.writeFileSync(configPath, makeInsecureConfig());

      const result = validateConfig(configPath);

      const saltIssues = result.issues.filter(
        i => i.constant !== null && i.constant.includes('SALT') && i.type === 'insecure_config'
      );
      expect(saltIssues.length).toBeGreaterThan(0);
    });

    it('should detect default table prefix', () => {
      const configPath = path.join(tempDir, 'wp-config.php');
      fs.writeFileSync(configPath, makeInsecureConfig());

      const result = validateConfig(configPath);

      const prefixIssue = result.issues.find(i => i.constant === '$table_prefix');
      expect(prefixIssue).toBeDefined();
      expect(prefixIssue!.severity).toBe('MEDIUM');
    });

    it('should not flag custom table prefix', () => {
      const configPath = path.join(tempDir, 'wp-config.php');
      fs.writeFileSync(configPath, makeSecureConfig());

      const result = validateConfig(configPath);

      const prefixIssue = result.issues.find(i => i.constant === '$table_prefix');
      expect(prefixIssue).toBeUndefined();
    });

    it('should detect WP_DEBUG enabled', () => {
      const configPath = path.join(tempDir, 'wp-config.php');
      fs.writeFileSync(configPath, makeDebugOnlyConfig());

      const result = validateConfig(configPath);

      expect(result.debugEnabled).toBe(true);

      const debugIssue = result.issues.find(i => i.constant === 'WP_DEBUG');
      expect(debugIssue).toBeDefined();
      expect(debugIssue!.type).toBe('debug_enabled');
      expect(debugIssue!.severity).toBe('MEDIUM');
    });

    it('should detect WP_DEBUG_DISPLAY enabled as HIGH severity', () => {
      const configPath = path.join(tempDir, 'wp-config.php');
      fs.writeFileSync(configPath, makeInsecureConfig());

      const result = validateConfig(configPath);

      const displayIssue = result.issues.find(i => i.constant === 'WP_DEBUG_DISPLAY');
      expect(displayIssue).toBeDefined();
      expect(displayIssue!.severity).toBe('HIGH');
    });

    it('should detect WP_DEBUG_LOG enabled', () => {
      const configPath = path.join(tempDir, 'wp-config.php');
      fs.writeFileSync(configPath, makeInsecureConfig());

      const result = validateConfig(configPath);

      const logIssue = result.issues.find(i => i.constant === 'WP_DEBUG_LOG');
      expect(logIssue).toBeDefined();
      expect(logIssue!.type).toBe('debug_enabled');
      expect(logIssue!.severity).toBe('LOW');
    });

    it('should detect SCRIPT_DEBUG enabled', () => {
      const configPath = path.join(tempDir, 'wp-config.php');
      fs.writeFileSync(configPath, makeInsecureConfig());

      const result = validateConfig(configPath);

      const scriptIssue = result.issues.find(i => i.constant === 'SCRIPT_DEBUG');
      expect(scriptIssue).toBeDefined();
      expect(scriptIssue!.severity).toBe('LOW');
    });

    it('should report correct line numbers', () => {
      const configPath = path.join(tempDir, 'wp-config.php');
      fs.writeFileSync(configPath, makeDebugOnlyConfig());

      const result = validateConfig(configPath);

      const debugIssue = result.issues.find(i => i.constant === 'WP_DEBUG');
      expect(debugIssue).toBeDefined();
      expect(debugIssue!.line).toBeGreaterThan(0);
    });

    it('should build severity breakdown correctly', () => {
      const configPath = path.join(tempDir, 'wp-config.php');
      fs.writeFileSync(configPath, makeInsecureConfig());

      const result = validateConfig(configPath);

      expect(result.bySeverity['HIGH']).toBeGreaterThan(0);
      expect(result.bySeverity['MEDIUM']).toBeGreaterThan(0);
      expect(result.bySeverity['LOW']).toBeGreaterThan(0);
    });

    it('should resolve relative paths', () => {
      const configPath = path.join(tempDir, 'wp-config.php');
      fs.writeFileSync(configPath, makeSecureConfig());

      const result = validateConfig(configPath);

      expect(path.isAbsolute(result.path)).toBe(true);
    });

    it('should handle DISALLOW_FILE_EDIT not set to true', () => {
      const configPath = path.join(tempDir, 'wp-config.php');
      fs.writeFileSync(configPath, `<?php
define('DISALLOW_FILE_EDIT', false);
define('AUTH_KEY', 'valid-key');
`);

      const result = validateConfig(configPath);

      const fileEditIssue = result.issues.find(i => i.constant === 'DISALLOW_FILE_EDIT');
      expect(fileEditIssue).toBeDefined();
      expect(fileEditIssue!.severity).toBe('MEDIUM');
    });

    it('should handle FORCE_SSL_ADMIN not set to true', () => {
      const configPath = path.join(tempDir, 'wp-config.php');
      fs.writeFileSync(configPath, `<?php
define('FORCE_SSL_ADMIN', false);
define('AUTH_KEY', 'valid-key');
`);

      const result = validateConfig(configPath);

      const sslIssue = result.issues.find(i => i.constant === 'FORCE_SSL_ADMIN');
      expect(sslIssue).toBeDefined();
      expect(sslIssue!.severity).toBe('MEDIUM');
    });
  });

  describe('argument validation', () => {
    it('should fail for non-existent path', async () => {
      const program = createProgram();
      registerConfigValidateCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'config:validate',
          '--path', '/nonexistent/path/12345',
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      expect(mockExit).toHaveBeenCalledWith(1);
      mockExit.mockRestore();
    });

    it('should accept --config-file option', async () => {
      const configPath = path.join(tempDir, 'wp-config.php');
      fs.writeFileSync(configPath, makeSecureConfig());

      const program = createProgram();
      registerConfigValidateCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'config:validate',
          '--config-file', configPath,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      expect(mockExit).toHaveBeenCalledWith(0);
      mockExit.mockRestore();
    });

    it('should look for wp-config.php in --path directory', async () => {
      fs.writeFileSync(path.join(tempDir, 'wp-config.php'), makeSecureConfig());

      const program = createProgram();
      registerConfigValidateCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'config:validate',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      expect(mockExit).toHaveBeenCalledWith(0);
      mockExit.mockRestore();
    });
  });

  describe('JSON output', () => {
    it('should produce valid JSON with --json flag', async () => {
      fs.writeFileSync(path.join(tempDir, 'wp-config.php'), makeSecureConfig());

      const program = createProgram();
      registerConfigValidateCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'config:validate',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);

      expect(result).toHaveProperty('path');
      expect(result).toHaveProperty('exists');
      expect(result).toHaveProperty('syntaxValid');
      expect(result).toHaveProperty('debugEnabled');
      expect(result).toHaveProperty('issues');
      expect(result).toHaveProperty('hasIssues');
      expect(result).toHaveProperty('bySeverity');
      mockExit.mockRestore();
    });

    it('should produce valid JSON for insecure config', async () => {
      fs.writeFileSync(path.join(tempDir, 'wp-config.php'), makeInsecureConfig());

      const program = createProgram();
      registerConfigValidateCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'config:validate',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.hasIssues).toBe(true);
      expect(result.issues.length).toBeGreaterThan(0);
      mockExit.mockRestore();
    });

    it('should produce valid JSON for error case', async () => {
      const program = createProgram();
      registerConfigValidateCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'config:validate',
          '--path', '/nonexistent/path/12345',
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const jsonCall = consoleSpy.mock.calls.find(
        (c: any) => typeof c[0] === 'string' && c[0].trim().startsWith('{')
      );
      expect(jsonCall).toBeDefined();
      const output = jsonCall![0] as string;
      expect(() => JSON.parse(output)).not.toThrow();
      const parsed = JSON.parse(output);
      expect(parsed).toHaveProperty('error');
      expect(mockExit).toHaveBeenCalledWith(1);
      mockExit.mockRestore();
    });
  });

  describe('human-readable output', () => {
    it('should print validation info without --json', async () => {
      fs.writeFileSync(path.join(tempDir, 'wp-config.php'), makeSecureConfig());

      const program = createProgram();
      registerConfigValidateCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'config:validate',
          '--path', tempDir,
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const allOutput = consoleSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('Validating WordPress configuration');
      expect(allOutput).toContain('Syntax:');
      expect(allOutput).toContain('Debug mode:');
      mockExit.mockRestore();
    });

    it('should print issues in human-readable output', async () => {
      fs.writeFileSync(path.join(tempDir, 'wp-config.php'), makeInsecureConfig());

      const program = createProgram();
      registerConfigValidateCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'config:validate',
          '--path', tempDir,
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const allOutput = consoleSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('Found');
      expect(allOutput).toContain('issue');
      expect(allOutput).toContain('Severity breakdown');
      mockExit.mockRestore();
    });
  });

  describe('exit codes', () => {
    it('should exit 0 when no issues found', async () => {
      fs.writeFileSync(path.join(tempDir, 'wp-config.php'), makeSecureConfig());

      const program = createProgram();
      registerConfigValidateCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'config:validate',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      expect(mockExit).toHaveBeenCalledWith(0);
      mockExit.mockRestore();
    });

    it('should exit 1 when issues found', async () => {
      fs.writeFileSync(path.join(tempDir, 'wp-config.php'), makeInsecureConfig());

      const program = createProgram();
      registerConfigValidateCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'config:validate',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      expect(mockExit).toHaveBeenCalledWith(1);
      mockExit.mockRestore();
    });

    it('should exit 1 when config file is missing', async () => {
      const program = createProgram();
      registerConfigValidateCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'config:validate',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      expect(mockExit).toHaveBeenCalledWith(1);
      mockExit.mockRestore();
    });
  });

  describe('debug-only config', () => {
    it('should detect debug enabled but no insecure keys', () => {
      const configPath = path.join(tempDir, 'wp-config.php');
      fs.writeFileSync(configPath, makeDebugOnlyConfig());

      const result = validateConfig(configPath);

      expect(result.exists).toBe(true);
      expect(result.hasIssues).toBe(true);
      expect(result.debugEnabled).toBe(true);

      const insecureIssues = result.issues.filter(i => i.type === 'insecure_config');
      expect(insecureIssues).toHaveLength(0);

      const debugIssues = result.issues.filter(i => i.type === 'debug_enabled');
      expect(debugIssues.length).toBeGreaterThan(0);
    });
  });

  describe('all auth key constants', () => {
    it('should detect all 8 empty auth key/salt constants', () => {
      const configPath = path.join(tempDir, 'wp-config.php');
      fs.writeFileSync(configPath, makeInsecureConfig());

      const result = validateConfig(configPath);

      const keyConstants = [
        'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY',
        'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT',
      ];

      for (const constant of keyConstants) {
        const issue = result.issues.find(
          i => i.constant === constant && i.type === 'insecure_config'
        );
        expect(issue).toBeDefined();
        expect(issue!.severity).toBe('HIGH');
      }
    });
  });
});
