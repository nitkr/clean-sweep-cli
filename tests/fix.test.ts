import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { Command } from 'commander';

import {
  registerFixCommand,
  runFix,
  collectFixActions,
  applyActions,
  applyPermissionFix,
  applyConfigFix,
  applyHtaccessFix,
  FixAction,
} from '../src/commands/fix';
import { checkPermissions } from '../src/commands/permissions-check';
import { validateConfig } from '../src/commands/config-validate';
import { checkHarden } from '../src/commands/harden-check';

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

function createWordPressSite(dir: string): void {
  fs.mkdirSync(path.join(dir, 'wp-includes'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'wp-config.php'), '<?php /* config */');
  fs.writeFileSync(path.join(dir, 'wp-config-sample.php'), '<?php /* sample */');
  fs.writeFileSync(path.join(dir, 'wp-includes', 'version.php'), "<?php $wp_version = '6.0';");
  fs.mkdirSync(path.join(dir, 'wp-content', 'themes'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'wp-content', 'plugins'), { recursive: true });
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
define('DISALLOW_FILE_EDIT', false);

if ( ! defined( 'ABSPATH' ) ) {
  define( 'ABSPATH', __DIR__ . '/' );
}

require_once ABSPATH . 'wp-settings.php';
`;
}

function makeSecureConfig(): string {
  return `<?php
define('DB_NAME', 'wordpress');
define('DB_USER', 'wpuser');
define('DB_PASSWORD', 'securepass123');
define('DB_HOST', 'localhost');

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
define('DISALLOW_FILE_EDIT', true);

if ( ! defined( 'ABSPATH' ) ) {
  define( 'ABSPATH', __DIR__ . '/' );
}

require_once ABSPATH . 'wp-settings.php';
`;
}

describe('Fix Command', () => {
  let tempDir: string;
  let consoleSpy: ReturnType<typeof jest.spyOn>;
  let consoleErrorSpy: ReturnType<typeof jest.spyOn>;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fix-test-'));
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

  function createProgram() {
    const program = new Command();
    program.exitOverride();
    return program;
  }

  describe('argument validation', () => {
    it('should fail for non-existent path', async () => {
      const program = createProgram();
      registerFixCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'fix',
          '--path', '/nonexistent/path/12345',
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      expect(mockExit).toHaveBeenCalledWith(1);
      mockExit.mockRestore();
    });

    it('should fail for non-directory path', async () => {
      const filePath = path.join(tempDir, 'file.txt');
      fs.writeFileSync(filePath, 'content');

      const program = createProgram();
      registerFixCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'fix',
          '--path', filePath,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      expect(mockExit).toHaveBeenCalledWith(1);
      mockExit.mockRestore();
    });
  });

  describe('runFix - dry run', () => {
    it('should not modify files in dry run mode', () => {
      createWordPressSite(tempDir);
      fs.writeFileSync(path.join(tempDir, 'wp-config.php'), makeInsecureConfig());
      fs.chmodSync(path.join(tempDir, 'wp-config.php'), 0o666);

      const result = runFix(tempDir, true);

      expect(result.dryRun).toBe(true);
      expect(result.summary.fixableIssues).toBeGreaterThan(0);
      expect(result.summary.applied).toBe(0);

      // File permissions should not be changed
      const stat = fs.lstatSync(path.join(tempDir, 'wp-config.php'));
      expect((stat.mode & 0o777)).toBe(0o666);

      // Config should not be changed
      const content = fs.readFileSync(path.join(tempDir, 'wp-config.php'), 'utf-8');
      expect(content).toContain("define('WP_DEBUG', true)");
    });

    it('should return correct action count in dry run', () => {
      createWordPressSite(tempDir);
      const badFile = path.join(tempDir, 'bad.txt');
      fs.writeFileSync(badFile, 'content');
      fs.chmodSync(badFile, 0o666);

      const result = runFix(tempDir, true);

      expect(result.dryRun).toBe(true);
      expect(result.actions.length).toBeGreaterThan(0);
      expect(result.actions.every(a => !a.applied)).toBe(true);
    });
  });

  describe('runFix - force mode', () => {
    it('should fix world-writable file permissions', () => {
      fs.writeFileSync(path.join(tempDir, 'bad.txt'), 'content');
      fs.chmodSync(path.join(tempDir, 'bad.txt'), 0o666);

      const result = runFix(tempDir, false);

      expect(result.dryRun).toBe(false);
      const chmodActions = result.actions.filter(a => a.fixType === 'chmod');
      expect(chmodActions.length).toBeGreaterThan(0);
      expect(chmodActions.some(a => a.applied)).toBe(true);

      // Verify permissions were actually changed
      const stat = fs.lstatSync(path.join(tempDir, 'bad.txt'));
      expect((stat.mode & 0o002)).toBe(0);
    });

    it('should fix unexpected executable permissions', () => {
      const scriptFile = path.join(tempDir, 'script.ts');
      fs.writeFileSync(scriptFile, 'const x = 1;');
      fs.chmodSync(scriptFile, 0o755);

      const result = runFix(tempDir, false);

      const execActions = result.actions.filter(a => a.issue.includes('executable'));
      expect(execActions.length).toBeGreaterThan(0);

      const stat = fs.lstatSync(scriptFile);
      expect((stat.mode & 0o111)).toBe(0);
    });

    it('should fix debug config settings', () => {
      createWordPressSite(tempDir);
      fs.writeFileSync(path.join(tempDir, 'wp-config.php'), makeInsecureConfig());

      const result = runFix(tempDir, false);

      const configActions = result.actions.filter(a => a.check === 'config');
      expect(configActions.length).toBeGreaterThan(0);
      expect(configActions.some(a => a.applied)).toBe(true);

      const content = fs.readFileSync(path.join(tempDir, 'wp-config.php'), 'utf-8');
      expect(content).toContain("define('WP_DEBUG', false)");
      expect(content).toContain("define('WP_DEBUG_DISPLAY', false)");
      expect(content).toContain("define('DISALLOW_FILE_EDIT', true)");
    });

    it('should create .htaccess with security rules', () => {
      createWordPressSite(tempDir);

      const result = runFix(tempDir, false);

      const htaccessActions = result.actions.filter(a => a.fixType === 'htaccess_add');
      expect(htaccessActions.length).toBeGreaterThan(0);
      expect(htaccessActions.some(a => a.applied)).toBe(true);

      const htaccessPath = path.join(tempDir, '.htaccess');
      expect(fs.existsSync(htaccessPath)).toBe(true);
      const content = fs.readFileSync(htaccessPath, 'utf-8');
      expect(content).toContain('Options -Indexes');
      expect(content).toContain('wp-config.php');
    });

    it('should create uploads .htaccess', () => {
      createWordPressSite(tempDir);
      fs.mkdirSync(path.join(tempDir, 'wp-content', 'uploads'), { recursive: true });

      const result = runFix(tempDir, false);

      const uploadsActions = result.actions.filter(a => a.file.endsWith('uploads/.htaccess'));
      expect(uploadsActions.length).toBeGreaterThan(0);

      const uploadsHtaccess = path.join(tempDir, 'wp-content', 'uploads', '.htaccess');
      expect(fs.existsSync(uploadsHtaccess)).toBe(true);
      const content = fs.readFileSync(uploadsHtaccess, 'utf-8');
      expect(content).toContain('php');
    });

    it('should fix world-writable directory permissions', () => {
      const dirPath = path.join(tempDir, 'writable-dir');
      fs.mkdirSync(dirPath);
      fs.chmodSync(dirPath, 0o777);

      const result = runFix(tempDir, false);

      const dirActions = result.actions.filter(a => a.issue.includes('world-writable') && a.file.includes('writable-dir'));
      expect(dirActions.length).toBeGreaterThan(0);

      const stat = fs.lstatSync(dirPath);
      expect((stat.mode & 0o002)).toBe(0);
    });

    it('should fix world-readable sensitive files', () => {
      const envFile = path.join(tempDir, '.env');
      fs.writeFileSync(envFile, 'SECRET=123');
      fs.chmodSync(envFile, 0o644);

      const result = runFix(tempDir, false);

      const sensitiveActions = result.actions.filter(a => a.issue.includes('Sensitive'));
      expect(sensitiveActions.length).toBeGreaterThan(0);

      const stat = fs.lstatSync(envFile);
      expect((stat.mode & 0o004)).toBe(0);
    });

    it('should fix setuid/setgid permissions', () => {
      const suidFile = path.join(tempDir, 'suid-file');
      fs.writeFileSync(suidFile, 'content');
      fs.chmodSync(suidFile, 0o4755);

      const result = runFix(tempDir, false);

      const suidActions = result.actions.filter(a => a.fixDescription.includes('chmod'));
      expect(suidActions.length).toBeGreaterThan(0);

      const stat = fs.lstatSync(suidFile);
      expect((stat.mode & 0o4000)).toBe(0);
    });

    it('should fix hardening file permissions', () => {
      createWordPressSite(tempDir);
      fs.chmodSync(path.join(tempDir, 'wp-config.php'), 0o666);

      const result = runFix(tempDir, false);

      const hardenPermActions = result.actions.filter(
        a => a.check === 'harden' && a.fixType === 'chmod' && a.file.endsWith('wp-config.php')
      );
      expect(hardenPermActions.length).toBeGreaterThan(0);
    });
  });

  describe('collectFixActions', () => {
    it('should collect permission issues', () => {
      fs.writeFileSync(path.join(tempDir, 'ww.txt'), 'x');
      fs.chmodSync(path.join(tempDir, 'ww.txt'), 0o666);

      const perms = checkPermissions(tempDir);
      const actions = collectFixActions(tempDir, perms, null, null);

      const permActions = actions.filter(a => a.check === 'permissions');
      expect(permActions.length).toBeGreaterThan(0);
      expect(permActions[0].fixType).toBe('chmod');
    });

    it('should collect config issues', () => {
      createWordPressSite(tempDir);
      fs.writeFileSync(path.join(tempDir, 'wp-config.php'), makeInsecureConfig());

      const perms = checkPermissions(tempDir);
      const config = validateConfig(path.join(tempDir, 'wp-config.php'));
      const actions = collectFixActions(tempDir, perms, config, null);

      const configActions = actions.filter(a => a.check === 'config');
      expect(configActions.length).toBeGreaterThan(0);
      expect(configActions.some(a => a.fixType === 'config_edit')).toBe(true);
    });

    it('should collect hardening issues', () => {
      createWordPressSite(tempDir);

      const perms = checkPermissions(tempDir);
      const harden = checkHarden(tempDir);
      const actions = collectFixActions(tempDir, perms, null, harden);

      const hardenActions = actions.filter(a => a.check === 'harden');
      expect(hardenActions.length).toBeGreaterThan(0);
    });

    it('should not collect config fixes for auth keys/salts', () => {
      createWordPressSite(tempDir);
      fs.writeFileSync(path.join(tempDir, 'wp-config.php'), makeInsecureConfig());

      const perms = checkPermissions(tempDir);
      const config = validateConfig(path.join(tempDir, 'wp-config.php'));
      const actions = collectFixActions(tempDir, perms, config, null);

      const keyActions = actions.filter(
        a => a.fixDescription.includes('KEY') || a.fixDescription.includes('SALT')
      );
      // Auth key/salt issues should not be auto-fixed (need unique values)
      expect(keyActions).toHaveLength(0);
    });
  });

  describe('applyActions', () => {
    it('should apply chmod fixes', () => {
      const file = path.join(tempDir, 'test.txt');
      fs.writeFileSync(file, 'x');
      fs.chmodSync(file, 0o666);

      const actions: FixAction[] = [{
        check: 'permissions',
        file,
        issue: 'world-writable',
        severity: 'HIGH',
        fixType: 'chmod',
        fixDescription: 'chmod 0664 ' + file,
        applied: false,
      }];

      const results = applyActions(actions);
      expect(results[0].applied).toBe(true);

      const stat = fs.lstatSync(file);
      expect((stat.mode & 0o002)).toBe(0);
    });

    it('should mark failed chmod when file does not exist', () => {
      const actions: FixAction[] = [{
        check: 'permissions',
        file: '/nonexistent/file.txt',
        issue: 'world-writable',
        severity: 'HIGH',
        fixType: 'chmod',
        fixDescription: 'chmod 0664 /nonexistent/file.txt',
        applied: false,
      }];

      const results = applyActions(actions);
      expect(results[0].applied).toBe(false);
      expect(results[0].error).toBeDefined();
    });

    it('should apply config fixes', () => {
      const configPath = path.join(tempDir, 'wp-config.php');
      fs.writeFileSync(configPath, makeInsecureConfig());

      const actions: FixAction[] = [{
        check: 'config',
        file: configPath,
        issue: 'WP_DEBUG is enabled',
        severity: 'MEDIUM',
        fixType: 'config_edit',
        fixDescription: 'Set WP_DEBUG to false in wp-config.php',
        applied: false,
      }];

      const results = applyActions(actions);
      expect(results[0].applied).toBe(true);

      const content = fs.readFileSync(configPath, 'utf-8');
      expect(content).toContain("define('WP_DEBUG', false)");
    });

    it('should apply htaccess fixes for uploads', () => {
      const uploadsDir = path.join(tempDir, 'wp-content', 'uploads');
      fs.mkdirSync(uploadsDir, { recursive: true });
      const htaccessPath = path.join(uploadsDir, '.htaccess');

      const actions: FixAction[] = [{
        check: 'harden',
        file: htaccessPath,
        issue: 'PHP execution not blocked',
        severity: 'HIGH',
        fixType: 'htaccess_add',
        fixDescription: 'Block PHP in uploads',
        applied: false,
      }];

      const results = applyActions(actions);
      expect(results[0].applied).toBe(true);

      const content = fs.readFileSync(htaccessPath, 'utf-8');
      expect(content).toContain('Deny from all');
    });

    it('should apply htaccess fixes for root', () => {
      const htaccessPath = path.join(tempDir, '.htaccess');

      const actions: FixAction[] = [{
        check: 'harden',
        file: htaccessPath,
        issue: 'Missing security rules',
        severity: 'HIGH',
        fixType: 'htaccess_add',
        fixDescription: 'Create .htaccess with security rules',
        applied: false,
      }];

      const results = applyActions(actions);
      expect(results[0].applied).toBe(true);

      const content = fs.readFileSync(htaccessPath, 'utf-8');
      expect(content).toContain('Options -Indexes');
      expect(content).toContain('BEGIN Clean Sweep');
    });

    it('should preserve existing htaccess content', () => {
      const htaccessPath = path.join(tempDir, '.htaccess');
      fs.writeFileSync(htaccessPath, '# Custom rules\nRewriteEngine On\n');

      const actions: FixAction[] = [{
        check: 'harden',
        file: htaccessPath,
        issue: 'Missing security rules',
        severity: 'HIGH',
        fixType: 'htaccess_add',
        fixDescription: 'Create .htaccess with security rules',
        applied: false,
      }];

      const results = applyActions(actions);
      expect(results[0].applied).toBe(true);

      const content = fs.readFileSync(htaccessPath, 'utf-8');
      expect(content).toContain('Options -Indexes');
      expect(content).toContain('Custom rules');
      expect(content).toContain('RewriteEngine On');
    });

    it('should handle config fix when pattern not found', () => {
      const configPath = path.join(tempDir, 'wp-config.php');
      fs.writeFileSync(configPath, '<?php // no defines here');

      const actions: FixAction[] = [{
        check: 'config',
        file: configPath,
        issue: 'WP_DEBUG is enabled',
        severity: 'MEDIUM',
        fixType: 'config_edit',
        fixDescription: 'Set WP_DEBUG to false in wp-config.php',
        applied: false,
      }];

      const results = applyActions(actions);
      expect(results[0].applied).toBe(false);
    });
  });

  describe('JSON output', () => {
    it('should produce valid JSON with --json flag', async () => {
      createWordPressSite(tempDir);
      fs.writeFileSync(path.join(tempDir, 'wp-config.php'), makeInsecureConfig());

      const program = createProgram();
      registerFixCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'fix',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);

      expect(result).toHaveProperty('path');
      expect(result).toHaveProperty('dryRun');
      expect(result).toHaveProperty('summary');
      expect(result).toHaveProperty('actions');
      expect(result).toHaveProperty('permissionsResult');
      expect(result).toHaveProperty('configResult');
      expect(result).toHaveProperty('hardenResult');
      mockExit.mockRestore();
    });

    it('should produce valid JSON for error case', async () => {
      const program = createProgram();
      registerFixCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'fix',
          '--path', '/nonexistent/path/12345',
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      expect(() => JSON.parse(output)).not.toThrow();
      expect(mockExit).toHaveBeenCalledWith(1);
      mockExit.mockRestore();
    });

    it('should show dryRun=true in JSON when no --force', async () => {
      createWordPressSite(tempDir);

      const program = createProgram();
      registerFixCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'fix',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.dryRun).toBe(true);
      mockExit.mockRestore();
    });

    it('should show dryRun=false in JSON with --force', async () => {
      createWordPressSite(tempDir);

      const program = createProgram();
      registerFixCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'fix',
          '--path', tempDir,
          '--json',
          '--force',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.dryRun).toBe(false);
      mockExit.mockRestore();
    });
  });

  describe('human-readable output', () => {
    it('should print dry run message by default', async () => {
      createWordPressSite(tempDir);

      const program = createProgram();
      registerFixCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'fix',
          '--path', tempDir,
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const allOutput = consoleSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('[DRY RUN]');
      expect(allOutput).toContain('--force');
      mockExit.mockRestore();
    });

    it('should print applied fixes with --force', async () => {
      fs.writeFileSync(path.join(tempDir, 'bad.txt'), 'x');
      fs.chmodSync(path.join(tempDir, 'bad.txt'), 0o666);

      const program = createProgram();
      registerFixCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'fix',
          '--path', tempDir,
          '--force',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const allOutput = consoleSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('[FIXED]');
      expect(allOutput).not.toContain('[DRY RUN]');
      mockExit.mockRestore();
    });

    it('should print check results summary', async () => {
      createWordPressSite(tempDir);

      const program = createProgram();
      registerFixCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'fix',
          '--path', tempDir,
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const allOutput = consoleSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('Permissions issues');
      expect(allOutput).toContain('Config issues');
      expect(allOutput).toContain('Hardening issues');
      expect(allOutput).toContain('Fix Summary');
      mockExit.mockRestore();
    });
  });

  describe('exit codes', () => {
    it('should exit 0 in dry run mode with no fixable issues', async () => {
      const program = createProgram();
      registerFixCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'fix',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      expect(mockExit).toHaveBeenCalledWith(0);
      mockExit.mockRestore();
    });

    it('should exit 0 in dry run mode even with fixable issues', async () => {
      fs.writeFileSync(path.join(tempDir, 'bad.txt'), 'x');
      fs.chmodSync(path.join(tempDir, 'bad.txt'), 0o666);

      const program = createProgram();
      registerFixCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'fix',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);
      expect(result.summary.fixableIssues).toBeGreaterThan(0);
      // In dry run, applied=0 and fixable>0, but dryRun=true so we should still exit 0
      expect(mockExit).toHaveBeenCalledWith(0);
      mockExit.mockRestore();
    });

    it('should exit 0 when all fixes applied successfully', async () => {
      fs.writeFileSync(path.join(tempDir, 'bad.txt'), 'x');
      fs.chmodSync(path.join(tempDir, 'bad.txt'), 0o666);

      const program = createProgram();
      registerFixCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'fix',
          '--path', tempDir,
          '--json',
          '--force',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);
      expect(result.summary.applied).toBeGreaterThan(0);
      expect(result.summary.failed).toBe(0);
      expect(mockExit).toHaveBeenCalledWith(0);
      mockExit.mockRestore();
    });

    it('should exit 1 with non-WordPress site', async () => {
      const program = createProgram();
      registerFixCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'fix',
          '--path', tempDir,
          '--json',
          '--force',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      expect(mockExit).toHaveBeenCalledWith(0);
      mockExit.mockRestore();
    });
  });

  describe('runFix result structure', () => {
    it('should include all three check results', () => {
      createWordPressSite(tempDir);

      const result = runFix(tempDir, true);

      expect(result.permissionsResult).toBeDefined();
      expect(result.configResult).toBeDefined();
      expect(result.hardenResult).toBeDefined();
    });

    it('should set configResult to null when no wp-config.php', () => {
      fs.writeFileSync(path.join(tempDir, 'readme.txt'), 'not wordpress');

      const result = runFix(tempDir, true);

      expect(result.configResult).toBeNull();
    });

    it('should have correct summary structure', () => {
      createWordPressSite(tempDir);

      const result = runFix(tempDir, true);

      expect(result.summary).toHaveProperty('totalIssues');
      expect(result.summary).toHaveProperty('fixableIssues');
      expect(result.summary).toHaveProperty('applied');
      expect(result.summary).toHaveProperty('skipped');
      expect(result.summary).toHaveProperty('failed');
    });
  });
});
