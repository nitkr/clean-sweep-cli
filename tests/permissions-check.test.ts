import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { Command } from 'commander';

import { registerPermissionsCheckCommand, checkPermissions } from '../src/commands/permissions-check';

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

describe('Permissions Check Command', () => {
  let tempDir: string;
  let consoleSpy: ReturnType<typeof jest.spyOn>;
  let consoleErrorSpy: ReturnType<typeof jest.spyOn>;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'perms-check-test-'));
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
      registerPermissionsCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'permissions:check',
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
      registerPermissionsCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'permissions:check',
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

  describe('world-writable files', () => {
    it('should detect world-writable files', () => {
      const filePath = path.join(tempDir, 'world-write.txt');
      fs.writeFileSync(filePath, 'content');
      fs.chmodSync(filePath, 0o666);

      const result = checkPermissions(tempDir);

      const wwIssue = result.issues.find(i => i.type === 'world_writable');
      expect(wwIssue).toBeDefined();
      expect(wwIssue!.severity).toBe('HIGH');
      expect(wwIssue!.suggestedMode).toBe('0664');
    });

    it('should not flag files without world-writable bit', () => {
      const filePath = path.join(tempDir, 'safe.txt');
      fs.writeFileSync(filePath, 'content');
      fs.chmodSync(filePath, 0o644);

      const result = checkPermissions(tempDir);

      const wwIssues = result.issues.filter(i => i.type === 'world_writable');
      expect(wwIssues).toHaveLength(0);
    });
  });

  describe('unexpected executable files', () => {
    it('should detect source files with executable permission', () => {
      const filePath = path.join(tempDir, 'script.ts');
      fs.writeFileSync(filePath, 'const x = 1;');
      fs.chmodSync(filePath, 0o755);

      const result = checkPermissions(tempDir);

      const execIssue = result.issues.find(i => i.type === 'unexpected_executable');
      expect(execIssue).toBeDefined();
      expect(execIssue!.severity).toBe('MEDIUM');
      expect(execIssue!.suggestedMode).toBe('0644');
    });

    it('should detect JSON files with executable permission', () => {
      const filePath = path.join(tempDir, 'config.json');
      fs.writeFileSync(filePath, '{}');
      fs.chmodSync(filePath, 0o755);

      const result = checkPermissions(tempDir);

      const execIssue = result.issues.find(i => i.type === 'unexpected_executable');
      expect(execIssue).toBeDefined();
    });

    it('should not flag .sh files as unexpected executable', () => {
      const filePath = path.join(tempDir, 'run.sh');
      fs.writeFileSync(filePath, '#!/bin/bash\necho hi');
      fs.chmodSync(filePath, 0o755);

      const result = checkPermissions(tempDir);

      const execIssue = result.issues.find(i => i.type === 'unexpected_executable');
      expect(execIssue).toBeUndefined();
    });

    it('should not flag non-executable files', () => {
      const filePath = path.join(tempDir, 'normal.txt');
      fs.writeFileSync(filePath, 'content');
      fs.chmodSync(filePath, 0o644);

      const result = checkPermissions(tempDir);

      const execIssue = result.issues.find(i => i.type === 'unexpected_executable');
      expect(execIssue).toBeUndefined();
    });
  });

  describe('setuid/setgid detection', () => {
    it('should detect setuid bit', () => {
      const filePath = path.join(tempDir, 'suid-file');
      fs.writeFileSync(filePath, 'content');
      fs.chmodSync(filePath, 0o4755);

      const result = checkPermissions(tempDir);

      const suidIssue = result.issues.find(i => i.type === 'setuid_setgid');
      expect(suidIssue).toBeDefined();
      expect(suidIssue!.severity).toBe('HIGH');
      expect(suidIssue!.suggestedMode).toBe('0755');
    });

    it('should detect setgid bit', () => {
      const filePath = path.join(tempDir, 'sgid-file');
      fs.writeFileSync(filePath, 'content');
      fs.chmodSync(filePath, 0o2755);

      const result = checkPermissions(tempDir);

      const sgidIssue = result.issues.find(i => i.type === 'setuid_setgid');
      expect(sgidIssue).toBeDefined();
    });
  });

  describe('sensitive file detection', () => {
    it('should detect world-readable .env files', () => {
      const filePath = path.join(tempDir, '.env');
      fs.writeFileSync(filePath, 'SECRET=123');
      fs.chmodSync(filePath, 0o644);

      const result = checkPermissions(tempDir);

      const sensitiveIssue = result.issues.find(i => i.type === 'world_readable_sensitive');
      expect(sensitiveIssue).toBeDefined();
      expect(sensitiveIssue!.severity).toBe('HIGH');
    });

    it('should detect world-readable .pem files', () => {
      const filePath = path.join(tempDir, 'key.pem');
      fs.writeFileSync(filePath, '-----BEGIN-----');
      fs.chmodSync(filePath, 0o644);

      const result = checkPermissions(tempDir);

      const sensitiveIssue = result.issues.find(i => i.type === 'world_readable_sensitive');
      expect(sensitiveIssue).toBeDefined();
    });

    it('should not flag .env files with restricted permissions', () => {
      const filePath = path.join(tempDir, '.env');
      fs.writeFileSync(filePath, 'SECRET=123');
      fs.chmodSync(filePath, 0o600);

      const result = checkPermissions(tempDir);

      const sensitiveIssue = result.issues.find(i => i.type === 'world_readable_sensitive');
      expect(sensitiveIssue).toBeUndefined();
    });
  });

  describe('world-writable directories', () => {
    it('should detect world-writable directories', () => {
      const dirPath = path.join(tempDir, 'writable-dir');
      fs.mkdirSync(dirPath);
      fs.chmodSync(dirPath, 0o777);

      const result = checkPermissions(tempDir);

      const dirIssue = result.issues.find(i => i.type === 'directory_world_writable');
      expect(dirIssue).toBeDefined();
      expect(dirIssue!.severity).toBe('MEDIUM');
    });

    it('should not flag directories without world-writable bit', () => {
      const dirPath = path.join(tempDir, 'safe-dir');
      fs.mkdirSync(dirPath);
      fs.chmodSync(dirPath, 0o755);

      const result = checkPermissions(tempDir);

      const dirIssue = result.issues.find(i => i.type === 'directory_world_writable');
      expect(dirIssue).toBeUndefined();
    });
  });

  describe('clean directory', () => {
    it('should return no issues for a clean directory', () => {
      fs.writeFileSync(path.join(tempDir, 'readme.md'), '# Hello');
      fs.chmodSync(path.join(tempDir, 'readme.md'), 0o644);
      fs.mkdirSync(path.join(tempDir, 'src'));
      fs.chmodSync(path.join(tempDir, 'src'), 0o755);

      const result = checkPermissions(tempDir);

      expect(result.hasIssues).toBe(false);
      expect(result.issues).toHaveLength(0);
      expect(result.totalChecked).toBeGreaterThan(0);
    });
  });

  describe('severity breakdown', () => {
    it('should count issues by severity', () => {
      const worldWrite = path.join(tempDir, 'ww.txt');
      fs.writeFileSync(worldWrite, 'x');
      fs.chmodSync(worldWrite, 0o666);

      const sourceExec = path.join(tempDir, 'src.js');
      fs.writeFileSync(sourceExec, 'var x=1;');
      fs.chmodSync(sourceExec, 0o755);

      const result = checkPermissions(tempDir);

      expect(result.bySeverity['HIGH']).toBeGreaterThanOrEqual(1);
      expect(result.bySeverity['MEDIUM']).toBeGreaterThanOrEqual(1);
    });
  });

  describe('JSON output', () => {
    it('should produce valid JSON with --json flag', async () => {
      fs.writeFileSync(path.join(tempDir, 'test.txt'), 'content');
      fs.chmodSync(path.join(tempDir, 'test.txt'), 0o644);

      const program = createProgram();
      registerPermissionsCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'permissions:check',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);

      expect(result).toHaveProperty('path');
      expect(result).toHaveProperty('totalFiles');
      expect(result).toHaveProperty('totalChecked');
      expect(result).toHaveProperty('issues');
      expect(result).toHaveProperty('hasIssues');
      expect(result).toHaveProperty('bySeverity');
      mockExit.mockRestore();
    });

    it('should produce valid JSON for error case', async () => {
      const program = createProgram();
      registerPermissionsCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'permissions:check',
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
      fs.writeFileSync(path.join(tempDir, 'test.txt'), 'content');
      fs.chmodSync(path.join(tempDir, 'test.txt'), 0o644);

      const program = createProgram();
      registerPermissionsCheckCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'permissions:check',
          '--path', tempDir,
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const allOutput = consoleSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('Checking permissions');
      expect(allOutput).toContain('Files scanned');
      mockExit.mockRestore();
    });

    it('should print issues in human-readable output', async () => {
      const filePath = path.join(tempDir, 'bad.txt');
      fs.writeFileSync(filePath, 'x');
      fs.chmodSync(filePath, 0o666);

      const program = createProgram();
      registerPermissionsCheckCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'permissions:check',
          '--path', tempDir,
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const allOutput = consoleSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('Found');
      expect(allOutput).toContain('permission issue');
      expect(allOutput).toContain('Severity breakdown');
      mockExit.mockRestore();
    });
  });

  describe('--fix flag', () => {
    it('should show chmod commands with --fix', async () => {
      const filePath = path.join(tempDir, 'bad.txt');
      fs.writeFileSync(filePath, 'x');
      fs.chmodSync(filePath, 0o666);

      const program = createProgram();
      registerPermissionsCheckCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'permissions:check',
          '--path', tempDir,
          '--fix',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const allOutput = consoleSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('chmod');
      expect(allOutput).toContain('Suggested fixes');
      mockExit.mockRestore();
    });
  });

  describe('exit codes', () => {
    it('should exit 0 when no issues found', async () => {
      fs.writeFileSync(path.join(tempDir, 'ok.txt'), 'content');
      fs.chmodSync(path.join(tempDir, 'ok.txt'), 0o644);

      const program = createProgram();
      registerPermissionsCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'permissions:check',
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
      const filePath = path.join(tempDir, 'bad.txt');
      fs.writeFileSync(filePath, 'x');
      fs.chmodSync(filePath, 0o666);

      const program = createProgram();
      registerPermissionsCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'permissions:check',
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

  describe('nested files', () => {
    it('should detect issues in subdirectories', () => {
      const subDir = path.join(tempDir, 'sub', 'deep');
      fs.mkdirSync(subDir, { recursive: true });

      const filePath = path.join(subDir, 'nested.txt');
      fs.writeFileSync(filePath, 'content');
      fs.chmodSync(filePath, 0o666);

      const result = checkPermissions(tempDir);

      const wwIssue = result.issues.find(
        i => i.type === 'world_writable' && i.file.includes('nested.txt')
      );
      expect(wwIssue).toBeDefined();
    });
  });

  describe('ignores node_modules and .git', () => {
    it('should not check files in node_modules', () => {
      const nmDir = path.join(tempDir, 'node_modules');
      fs.mkdirSync(nmDir);
      const filePath = path.join(nmDir, 'pkg.js');
      fs.writeFileSync(filePath, 'content');
      fs.chmodSync(filePath, 0o777);

      const result = checkPermissions(tempDir);

      const nmIssues = result.issues.filter(i => i.file.includes('node_modules'));
      expect(nmIssues).toHaveLength(0);
    });

    it('should not check files in .git', () => {
      const gitDir = path.join(tempDir, '.git');
      fs.mkdirSync(gitDir);
      const filePath = path.join(gitDir, 'config');
      fs.writeFileSync(filePath, 'content');
      fs.chmodSync(filePath, 0o777);

      const result = checkPermissions(tempDir);

      const gitIssues = result.issues.filter(i => i.file.includes('.git'));
      expect(gitIssues).toHaveLength(0);
    });
  });
});
