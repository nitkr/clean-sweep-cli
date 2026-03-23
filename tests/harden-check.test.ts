import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { Command } from 'commander';

import {
  registerHardenCheckCommand,
  checkHarden,
  checkHtaccess,
  checkFilePermissions,
  checkSecurityPlugins,
  generateRecommendations,
  calculateScore,
  isWordPressSite,
} from '../src/commands/harden-check';

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

describe('Harden Check Command', () => {
  let tempDir: string;
  let consoleSpy: ReturnType<typeof jest.spyOn>;
  let consoleErrorSpy: ReturnType<typeof jest.spyOn>;
  let consoleWarnSpy: ReturnType<typeof jest.spyOn>;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'harden-check-test-'));
    consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
    consoleSpy.mockRestore();
    consoleErrorSpy.mockRestore();
    consoleWarnSpy.mockRestore();
  });

  function createProgram() {
    const program = new Command();
    program.exitOverride();
    return program;
  }

  describe('argument validation', () => {
    it('should fail for non-existent path', async () => {
      const program = createProgram();
      registerHardenCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'harden:check',
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
      registerHardenCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'harden:check',
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

  describe('isWordPressSite', () => {
    it('should detect a WordPress site', () => {
      createWordPressSite(tempDir);
      expect(isWordPressSite(tempDir)).toBe(true);
    });

    it('should return false for non-WordPress directory', () => {
      fs.writeFileSync(path.join(tempDir, 'readme.txt'), 'not wordpress');
      expect(isWordPressSite(tempDir)).toBe(false);
    });

    it('should detect WordPress with just wp-content structure', () => {
      fs.mkdirSync(path.join(tempDir, 'wp-content', 'themes'), { recursive: true });
      fs.mkdirSync(path.join(tempDir, 'wp-content', 'plugins'), { recursive: true });
      expect(isWordPressSite(tempDir)).toBe(true);
    });
  });

  describe('checkHtaccess', () => {
    it('should flag missing .htaccess rules', () => {
      createWordPressSite(tempDir);

      const results = checkHtaccess(tempDir);

      expect(results.length).toBeGreaterThan(0);
      const missingRules = results.filter((r) => !r.present);
      expect(missingRules.length).toBeGreaterThan(0);
    });

    it('should detect present .htaccess rules', () => {
      createWordPressSite(tempDir);

      const htaccessContent = [
        'Options -Indexes',
        '<Files wp-config.php>',
        '  Require all denied',
        '</Files>',
        'ServerSignature Off',
      ].join('\n');
      fs.writeFileSync(path.join(tempDir, '.htaccess'), htaccessContent);

      const results = checkHtaccess(tempDir);

      const indexingRule = results.find((r) => r.rule === 'disable_indexing');
      expect(indexingRule?.present).toBe(true);

      const wpConfigRule = results.find((r) => r.rule === 'protect_wpconfig');
      expect(wpConfigRule?.present).toBe(true);

      const serverSigRule = results.find((r) => r.rule === 'disable_server_signature');
      expect(serverSigRule?.present).toBe(true);
    });

    it('should check uploads directory .htaccess', () => {
      createWordPressSite(tempDir);

      const uploadsDir = path.join(tempDir, 'wp-content', 'uploads');
      fs.mkdirSync(uploadsDir, { recursive: true });
      fs.writeFileSync(path.join(uploadsDir, '.htaccess'), 'deny from all\n<FilesMatch "\\.php$">');

      const results = checkHtaccess(tempDir);

      const uploadsRule = results.find((r) => r.rule === 'uploads_block_php');
      expect(uploadsRule?.present).toBe(true);
    });

    it('should flag missing uploads .htaccess', () => {
      createWordPressSite(tempDir);

      const results = checkHtaccess(tempDir);

      const uploadsRule = results.find((r) => r.rule === 'uploads_block_php');
      expect(uploadsRule?.present).toBe(false);
      expect(uploadsRule?.severity).toBe('HIGH');
    });

    it('should flag xmlrpc.php rule', () => {
      createWordPressSite(tempDir);
      fs.writeFileSync(path.join(tempDir, '.htaccess'), 'Options -Indexes');

      const results = checkHtaccess(tempDir);

      const xmlrpcRule = results.find((r) => r.rule === 'block_xmlrpc');
      expect(xmlrpcRule?.present).toBe(false);
      expect(xmlrpcRule?.severity).toBe('HIGH');
    });
  });

  describe('checkFilePermissions', () => {
    it('should detect world-writable wp-config.php', () => {
      createWordPressSite(tempDir);
      fs.chmodSync(path.join(tempDir, 'wp-config.php'), 0o666);

      const issues = checkFilePermissions(tempDir);

      const wpConfigIssue = issues.find((i) => i.file.endsWith('wp-config.php'));
      expect(wpConfigIssue).toBeDefined();
      expect(wpConfigIssue?.severity).toBe('HIGH');
    });

    it('should flag group/other permissions on wp-config.php', () => {
      createWordPressSite(tempDir);
      fs.chmodSync(path.join(tempDir, 'wp-config.php'), 0o640);

      const issues = checkFilePermissions(tempDir);

      const wpConfigIssue = issues.find((i) => i.file.endsWith('wp-config.php'));
      expect(wpConfigIssue).toBeDefined();
      expect(wpConfigIssue?.severity).toBe('MEDIUM');
    });

    it('should not flag properly restricted wp-config.php', () => {
      createWordPressSite(tempDir);
      fs.chmodSync(path.join(tempDir, 'wp-config.php'), 0o400);

      const issues = checkFilePermissions(tempDir);

      const wpConfigIssue = issues.find((i) => i.file.endsWith('wp-config.php'));
      expect(wpConfigIssue).toBeUndefined();
    });

    it('should detect world-writable wp-content', () => {
      createWordPressSite(tempDir);
      fs.chmodSync(path.join(tempDir, 'wp-content'), 0o777);

      const issues = checkFilePermissions(tempDir);

      const wpContentIssue = issues.find((i) => i.file.endsWith('wp-content'));
      expect(wpContentIssue).toBeDefined();
      expect(wpContentIssue?.severity).toBe('HIGH');
    });

    it('should not flag properly configured wp-content', () => {
      createWordPressSite(tempDir);
      fs.chmodSync(path.join(tempDir, 'wp-content'), 0o755);

      const issues = checkFilePermissions(tempDir);

      const wpContentIssue = issues.find((i) => i.file.endsWith('wp-content'));
      expect(wpContentIssue).toBeUndefined();
    });

    it('should detect world-writable .htaccess', () => {
      createWordPressSite(tempDir);
      fs.writeFileSync(path.join(tempDir, '.htaccess'), 'Options -Indexes');
      fs.chmodSync(path.join(tempDir, '.htaccess'), 0o666);

      const issues = checkFilePermissions(tempDir);

      const htaccessIssue = issues.find((i) => i.file.endsWith('.htaccess'));
      expect(htaccessIssue).toBeDefined();
      expect(htaccessIssue?.severity).toBe('HIGH');
    });

    it('should return empty issues for no WP files', () => {
      const issues = checkFilePermissions(tempDir);
      expect(issues).toHaveLength(0);
    });
  });

  describe('checkSecurityPlugins', () => {
    it('should detect installed security plugins', () => {
      createWordPressSite(tempDir);
      fs.mkdirSync(path.join(tempDir, 'wp-content', 'plugins', 'wordfence'), { recursive: true });
      fs.mkdirSync(path.join(tempDir, 'wp-content', 'plugins', 'limit-login-attempts-reloaded'), { recursive: true });

      const plugins = checkSecurityPlugins(tempDir);

      const wordfence = plugins.find((p) => p.name === 'Wordfence');
      expect(wordfence?.found).toBe(true);
      expect(wordfence?.category).toBe('firewall');

      const loginLock = plugins.find((p) => p.name === 'Limit Login Attempts Reloaded');
      expect(loginLock?.found).toBe(true);
      expect(loginLock?.category).toBe('login_protection');
    });

    it('should report missing security plugins', () => {
      createWordPressSite(tempDir);

      const plugins = checkSecurityPlugins(tempDir);

      const foundPlugins = plugins.filter((p) => p.found);
      expect(foundPlugins).toHaveLength(0);

      const allPlugins = plugins.filter((p) => !p.found);
      expect(allPlugins.length).toBeGreaterThan(0);
    });

    it('should categorize plugins correctly', () => {
      createWordPressSite(tempDir);
      fs.mkdirSync(path.join(tempDir, 'wp-content', 'plugins', 'sucuri-scanner'), { recursive: true });

      const plugins = checkSecurityPlugins(tempDir);

      const sucuri = plugins.find((p) => p.name === 'Sucuri Security');
      expect(sucuri?.found).toBe(true);
      expect(sucuri?.category).toBe('firewall');
    });
  });

  describe('generateRecommendations', () => {
    it('should generate fail recommendations for missing rules', () => {
      const htaccessChecks = [
        { file: '/test/.htaccess', rule: 'disable_indexing', present: false, severity: 'HIGH' as const, description: 'Test', recommendation: 'Add rule' },
      ];
      const recommendations = generateRecommendations(htaccessChecks, [], []);

      const failed = recommendations.filter((r) => r.status === 'fail');
      expect(failed.length).toBeGreaterThan(0);
    });

    it('should generate pass recommendations for present rules', () => {
      const htaccessChecks = [
        { file: '/test/.htaccess', rule: 'disable_indexing', present: true, severity: 'HIGH' as const, description: 'Test', recommendation: 'Add rule' },
      ];
      const recommendations = generateRecommendations(htaccessChecks, [], []);

      const passed = recommendations.filter((r) => r.status === 'pass');
      expect(passed.length).toBeGreaterThan(0);
    });

    it('should generate warning for missing firewall', () => {
      const plugins = [
        { name: 'Login LockDown', found: true, category: 'login_protection' as const },
      ];
      const recommendations = generateRecommendations([], [], plugins);

      const warnings = recommendations.filter((r) => r.status === 'warning');
      const firewallWarning = warnings.find((r) => r.details?.includes('firewall'));
      expect(firewallWarning).toBeDefined();
    });

    it('should recommend installing plugins when none found', () => {
      const plugins = [
        { name: 'Wordfence', found: false, category: 'firewall' as const },
      ];
      const recommendations = generateRecommendations([], [], plugins);

      const installRec = recommendations.find((r) => r.details?.includes('No known security plugins'));
      expect(installRec).toBeDefined();
      expect(installRec?.severity).toBe('HIGH');
    });
  });

  describe('calculateScore', () => {
    it('should calculate score correctly for all passing', () => {
      const recommendations = [
        { category: 'test', recommendation: 'ok', severity: 'HIGH' as const, status: 'pass' as const },
        { category: 'test', recommendation: 'ok', severity: 'MEDIUM' as const, status: 'pass' as const },
      ];
      const { score, maxScore } = calculateScore(recommendations);

      expect(score).toBe(maxScore);
    });

    it('should give partial score for warnings', () => {
      const recommendations = [
        { category: 'test', recommendation: 'warn', severity: 'HIGH' as const, status: 'warning' as const },
      ];
      const { score, maxScore } = calculateScore(recommendations);

      expect(score).toBeLessThan(maxScore);
      expect(score).toBeGreaterThan(0);
    });

    it('should give zero score for failures', () => {
      const recommendations = [
        { category: 'test', recommendation: 'fail', severity: 'HIGH' as const, status: 'fail' as const },
      ];
      const { score } = calculateScore(recommendations);

      expect(score).toBe(0);
    });
  });

  describe('checkHarden', () => {
    it('should return full result for WordPress site', () => {
      createWordPressSite(tempDir);

      const result = checkHarden(tempDir);

      expect(result.path).toBe(tempDir);
      expect(result.isWordPress).toBe(true);
      expect(result.htaccessChecks.length).toBeGreaterThan(0);
      expect(result.recommendations.length).toBeGreaterThan(0);
      expect(result.maxScore).toBeGreaterThan(0);
      expect(result.bySeverity).toBeDefined();
    });

    it('should return result with hasIssues for insecure site', () => {
      createWordPressSite(tempDir);
      fs.chmodSync(path.join(tempDir, 'wp-config.php'), 0o666);

      const result = checkHarden(tempDir);

      expect(result.filePermissionIssues.length).toBeGreaterThan(0);
      expect(result.bySeverity['HIGH']).toBeGreaterThan(0);
    });

    it('should detect non-WordPress site', () => {
      fs.writeFileSync(path.join(tempDir, 'readme.txt'), 'not wordpress');

      const result = checkHarden(tempDir);

      expect(result.isWordPress).toBe(false);
    });
  });

  describe('JSON output', () => {
    it('should produce valid JSON with --json flag', async () => {
      createWordPressSite(tempDir);

      const program = createProgram();
      registerHardenCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'harden:check',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);

      expect(result).toHaveProperty('path');
      expect(result).toHaveProperty('isWordPress');
      expect(result).toHaveProperty('htaccessChecks');
      expect(result).toHaveProperty('filePermissionIssues');
      expect(result).toHaveProperty('securityPlugins');
      expect(result).toHaveProperty('recommendations');
      expect(result).toHaveProperty('score');
      expect(result).toHaveProperty('maxScore');
      expect(result).toHaveProperty('bySeverity');
      mockExit.mockRestore();
    });

    it('should produce valid JSON for error case', async () => {
      const program = createProgram();
      registerHardenCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'harden:check',
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
  });

  describe('human-readable output', () => {
    it('should print check info without --json', async () => {
      createWordPressSite(tempDir);

      const program = createProgram();
      registerHardenCheckCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'harden:check',
          '--path', tempDir,
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const allOutput = consoleSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('Checking WordPress security hardening');
      expect(allOutput).toContain('.htaccess Security Rules');
      expect(allOutput).toContain('File Permissions');
      expect(allOutput).toContain('Security Plugins');
      expect(allOutput).toContain('Recommendations');
      expect(allOutput).toContain('Hardening Score');
      mockExit.mockRestore();
    });

    it('should warn for non-WordPress site', async () => {
      fs.writeFileSync(path.join(tempDir, 'readme.txt'), 'not wordpress');

      const program = createProgram();
      registerHardenCheckCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'harden:check',
          '--path', tempDir,
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      expect(consoleWarnSpy).toHaveBeenCalledWith(
        'Warning: Directory does not appear to be a WordPress installation'
      );
      mockExit.mockRestore();
    });

    it('should display missing rules as [MISSING]', async () => {
      createWordPressSite(tempDir);

      const program = createProgram();
      registerHardenCheckCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'harden:check',
          '--path', tempDir,
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const allOutput = consoleSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('[MISSING]');
      expect(allOutput).toContain('[FAIL]');
      mockExit.mockRestore();
    });

    it('should display detected plugins as [OK]', async () => {
      createWordPressSite(tempDir);
      fs.mkdirSync(path.join(tempDir, 'wp-content', 'plugins', 'wordfence'), { recursive: true });

      const program = createProgram();
      registerHardenCheckCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'harden:check',
          '--path', tempDir,
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const allOutput = consoleSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('[OK] Wordfence');
      mockExit.mockRestore();
    });
  });

  describe('exit codes', () => {
    it('should exit 1 when high severity issues found', async () => {
      createWordPressSite(tempDir);

      const program = createProgram();
      registerHardenCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'harden:check',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      expect(mockExit).toHaveBeenCalledWith(1);
      mockExit.mockRestore();
    });

    it('should exit 0 when properly hardened', async () => {
      createWordPressSite(tempDir);

      // Create a fully hardened site
      fs.writeFileSync(path.join(tempDir, '.htaccess'), [
        'Options -Indexes',
        '<Files wp-config.php>',
        '  Require all denied',
        '</Files>',
        '<Files .htaccess>',
        '  Require all denied',
        '</Files>',
        '<FilesMatch "\\.php$">',
        '  Require all denied',
        '</FilesMatch>',
        'ServerSignature Off',
        '<Files readme.html>',
        '  Require all denied',
        '</Files>',
        '<Files xmlrpc.php>',
        '  Require all denied',
        '</Files>',
        '<Files wp-includes>',
        '  Require all denied',
        '</Files>',
        'RewriteCond %{REQUEST_URI} ^/wp-admin',
      ].join('\n'));

      fs.chmodSync(path.join(tempDir, 'wp-config.php'), 0o400);
      fs.mkdirSync(path.join(tempDir, 'wp-content', 'uploads'), { recursive: true });
      fs.writeFileSync(path.join(tempDir, 'wp-content', 'uploads', '.htaccess'), '<FilesMatch "\\.php$">');
      fs.mkdirSync(path.join(tempDir, 'wp-content', 'plugins', 'wordfence'), { recursive: true });
      fs.mkdirSync(path.join(tempDir, 'wp-content', 'plugins', 'limit-login-attempts-reloaded'), { recursive: true });

      const program = createProgram();
      registerHardenCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'harden:check',
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
});
