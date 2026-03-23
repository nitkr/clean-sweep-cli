import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { Command } from 'commander';
import { registerQuarantineCommand } from '../src/commands/quarantine';

function createTestCliOptions(overrides: Partial<{
  dryRun: boolean;
  force: boolean;
  json: boolean;
  path: string;
  verbose: boolean;
  logLevel: string;
}> = {}) {
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

describe('Quarantine Command', () => {
  let tempDir: string;
  let consoleSpy: jest.SpyInstance;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'quarantine-test-'));
    consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
    consoleSpy.mockRestore();
  });

  function createProgram() {
    const program = new Command();
    program.exitOverride();
    return program;
  }

  describe('dry-run mode (default)', () => {
    it('should report no threats for clean directory', async () => {
      fs.writeFileSync(path.join(tempDir, 'clean.php'), '<?php echo "hello"; ?>');

      const program = createProgram();
      registerQuarantineCommand(program, createTestCliOptions({ path: tempDir, json: true }));

      await program.parseAsync(['node', 'test', 'quarantine', '--path', tempDir, '--json']);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      const result = JSON.parse(output);
      expect(result.success).toBe(true);
      expect(result.dryRun).toBe(true);
      expect(result.threatsFound).toBe(0);
      expect(result.filesQuarantined).toEqual([]);
    });

    it('should list infected files without moving them', async () => {
      fs.writeFileSync(path.join(tempDir, 'malware.php'), '<?php eval($_GET["cmd"]); ?>');

      const program = createProgram();
      registerQuarantineCommand(program, createTestCliOptions({ path: tempDir, json: true }));

      await program.parseAsync(['node', 'test', 'quarantine', '--path', tempDir, '--json']);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      const result = JSON.parse(output);
      expect(result.dryRun).toBe(true);
      expect(result.threatsFound).toBeGreaterThan(0);
      expect(result.filesQuarantined.length).toBeGreaterThan(0);
      expect(result.filesQuarantined[0]).toContain('malware.php');

      expect(fs.existsSync(path.join(tempDir, 'malware.php'))).toBe(true);
      expect(fs.existsSync(path.join(tempDir, 'quarantine'))).toBe(false);
    });

    it('should output human-readable format without --json', async () => {
      fs.writeFileSync(path.join(tempDir, 'backdoor.php'), '<?php eval($cmd); ?>');

      const program = createProgram();
      registerQuarantineCommand(program, createTestCliOptions({ path: tempDir, json: false }));

      await program.parseAsync(['node', 'test', 'quarantine', '--path', tempDir]);

      const allOutput = consoleSpy.mock.calls.map(c => String(c[0])).join('\n');
      expect(allOutput).toContain('Found');
      expect(allOutput).toContain('threat(s)');
      expect(allOutput).toContain('Dry run mode');
    });

    it('should detect multiple threats in multiple files', async () => {
      fs.writeFileSync(path.join(tempDir, 'evil1.php'), '<?php eval($cmd); base64_decode($x); ?>');
      fs.writeFileSync(path.join(tempDir, 'evil2.php'), '<?php shell_exec("ls"); ?>');

      const program = createProgram();
      registerQuarantineCommand(program, createTestCliOptions({ path: tempDir, json: true }));

      await program.parseAsync(['node', 'test', 'quarantine', '--path', tempDir, '--json']);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      const result = JSON.parse(output);
      expect(result.threatsFound).toBeGreaterThanOrEqual(3);
      expect(result.filesQuarantined.length).toBe(2);
    });

    it('should not scan files in quarantine directory', async () => {
      const quarantineSubDir = path.join(tempDir, 'quarantine', 'old-session');
      fs.mkdirSync(quarantineSubDir, { recursive: true });
      fs.writeFileSync(path.join(quarantineSubDir, 'old-malware.php'), '<?php eval($cmd); ?>');
      fs.writeFileSync(path.join(tempDir, 'clean.php'), '<?php echo "hello"; ?>');

      const program = createProgram();
      registerQuarantineCommand(program, createTestCliOptions({ path: tempDir, json: true }));

      await program.parseAsync(['node', 'test', 'quarantine', '--path', tempDir, '--json']);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      const result = JSON.parse(output);
      expect(result.threatsFound).toBe(0);
    });
  });

  describe('force mode', () => {
    it('should actually quarantine infected files with --force', async () => {
      fs.writeFileSync(path.join(tempDir, 'malware.php'), '<?php eval($cmd); ?>');
      fs.writeFileSync(path.join(tempDir, 'safe.php'), '<?php echo "hello"; ?>');

      const program = createProgram();
      registerQuarantineCommand(program, createTestCliOptions({ path: tempDir, json: true, force: true }));

      await program.parseAsync(['node', 'test', 'quarantine', '--path', tempDir, '--force', '--json']);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.success).toBe(true);
      expect(result.dryRun).toBe(false);
      expect(result.filesQuarantined.length).toBe(1);
      expect(result.quarantineDir).toContain('quarantine');
      expect(result.backupDir).toContain('quarantine-backup');

      expect(fs.existsSync(path.join(tempDir, 'malware.php'))).toBe(false);
      expect(fs.existsSync(path.join(tempDir, 'safe.php'))).toBe(true);
      expect(fs.existsSync(result.quarantineDir)).toBe(true);
      expect(fs.existsSync(result.backupDir)).toBe(true);
    });

    it('should create quarantine directory with timestamp', async () => {
      fs.writeFileSync(path.join(tempDir, 'malware.php'), '<?php eval($cmd); ?>');

      const program = createProgram();
      registerQuarantineCommand(program, createTestCliOptions({ path: tempDir, json: true, force: true }));

      await program.parseAsync(['node', 'test', 'quarantine', '--path', tempDir, '--force', '--json']);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.quarantineDir).toMatch(/quarantine\/\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}/);
    });

    it('should preserve original directory structure in quarantine', async () => {
      const subDir = path.join(tempDir, 'wp-content', 'plugins');
      fs.mkdirSync(subDir, { recursive: true });
      fs.writeFileSync(path.join(subDir, 'evil-plugin.php'), '<?php eval($cmd); ?>');

      const program = createProgram();
      registerQuarantineCommand(program, createTestCliOptions({ path: tempDir, json: true, force: true }));

      await program.parseAsync(['node', 'test', 'quarantine', '--path', tempDir, '--force', '--json']);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.success).toBe(true);
      expect(fs.existsSync(path.join(subDir, 'evil-plugin.php'))).toBe(false);

      const quarantinedFile = path.join(
        result.quarantineDir,
        'wp-content',
        'plugins',
        'evil-plugin.php'
      );
      expect(fs.existsSync(quarantinedFile)).toBe(true);
    });

    it('should create backup before quarantining', async () => {
      const malwareContent = '<?php eval($cmd); ?>';
      fs.writeFileSync(path.join(tempDir, 'malware.php'), malwareContent);

      const program = createProgram();
      registerQuarantineCommand(program, createTestCliOptions({ path: tempDir, json: true, force: true }));

      await program.parseAsync(['node', 'test', 'quarantine', '--path', tempDir, '--force', '--json']);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.backupDir).not.toBeNull();
      expect(fs.existsSync(result.backupDir)).toBe(true);

      const backupFile = path.join(result.backupDir, 'malware.php');
      expect(fs.existsSync(backupFile)).toBe(true);
      expect(fs.readFileSync(backupFile, 'utf-8')).toBe(malwareContent);
    });

    it('should handle multiple infected files in force mode', async () => {
      fs.writeFileSync(path.join(tempDir, 'mal1.php'), '<?php eval($cmd); ?>');
      fs.writeFileSync(path.join(tempDir, 'mal2.php'), '<?php shell_exec("ls"); ?>');
      fs.writeFileSync(path.join(tempDir, 'mal3.js'), 'eval("alert(1)")');

      const program = createProgram();
      registerQuarantineCommand(program, createTestCliOptions({ path: tempDir, json: true, force: true }));

      await program.parseAsync(['node', 'test', 'quarantine', '--path', tempDir, '--force', '--json']);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.success).toBe(true);
      expect(result.filesQuarantined.length).toBe(3);
      expect(fs.existsSync(path.join(tempDir, 'mal1.php'))).toBe(false);
      expect(fs.existsSync(path.join(tempDir, 'mal2.php'))).toBe(false);
      expect(fs.existsSync(path.join(tempDir, 'mal3.js'))).toBe(false);
    });
  });

  describe('JSON output', () => {
    it('should output valid JSON with --json flag', async () => {
      fs.writeFileSync(path.join(tempDir, 'clean.php'), '<?php echo "hello"; ?>');

      const program = createProgram();
      registerQuarantineCommand(program, createTestCliOptions({ path: tempDir, json: true }));

      await program.parseAsync(['node', 'test', 'quarantine', '--path', tempDir, '--json']);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      expect(() => JSON.parse(output)).not.toThrow();
    });

    it('should include all expected fields in JSON output', async () => {
      fs.writeFileSync(path.join(tempDir, 'clean.php'), '<?php echo "hello"; ?>');

      const program = createProgram();
      registerQuarantineCommand(program, createTestCliOptions({ path: tempDir, json: true }));

      await program.parseAsync(['node', 'test', 'quarantine', '--path', tempDir, '--json']);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      const result = JSON.parse(output);

      expect(result).toHaveProperty('success');
      expect(result).toHaveProperty('dryRun');
      expect(result).toHaveProperty('threatsFound');
      expect(result).toHaveProperty('filesQuarantined');
      expect(result).toHaveProperty('quarantineDir');
      expect(result).toHaveProperty('backupDir');
      expect(result).toHaveProperty('errors');
    });

    it('should output valid JSON for threats found in dry-run', async () => {
      fs.writeFileSync(path.join(tempDir, 'malware.php'), '<?php eval($cmd); ?>');

      const program = createProgram();
      registerQuarantineCommand(program, createTestCliOptions({ path: tempDir, json: true }));

      await program.parseAsync(['node', 'test', 'quarantine', '--path', tempDir, '--json']);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.success).toBe(true);
      expect(result.dryRun).toBe(true);
      expect(result.threatsFound).toBeGreaterThan(0);
      expect(Array.isArray(result.filesQuarantined)).toBe(true);
    });
  });

  describe('error handling', () => {
    it('should fail for non-existent path', async () => {
      const program = createProgram();
      registerQuarantineCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync(['node', 'test', 'quarantine', '--path', '/nonexistent/path/12345', '--json']);
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
      registerQuarantineCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync(['node', 'test', 'quarantine', '--path', filePath, '--json']);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      expect(mockExit).toHaveBeenCalledWith(1);
      mockExit.mockRestore();
    });
  });

  describe('edge cases', () => {
    it('should handle empty directory', async () => {
      const program = createProgram();
      registerQuarantineCommand(program, createTestCliOptions({ path: tempDir, json: true }));

      await program.parseAsync(['node', 'test', 'quarantine', '--path', tempDir, '--json']);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.success).toBe(true);
      expect(result.threatsFound).toBe(0);
    });

    it('should handle JS threats', async () => {
      fs.writeFileSync(path.join(tempDir, 'malicious.js'), 'eval("alert(1)")');

      const program = createProgram();
      registerQuarantineCommand(program, createTestCliOptions({ path: tempDir, json: true, force: true }));

      await program.parseAsync(['node', 'test', 'quarantine', '--path', tempDir, '--force', '--json']);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.success).toBe(true);
      expect(result.filesQuarantined.length).toBe(1);
      expect(fs.existsSync(path.join(tempDir, 'malicious.js'))).toBe(false);
    });

    it('should not duplicate files with multiple threats', async () => {
      fs.writeFileSync(
        path.join(tempDir, 'multi.php'),
        '<?php eval($cmd); base64_decode($data); shell_exec("ls"); ?>'
      );

      const program = createProgram();
      registerQuarantineCommand(program, createTestCliOptions({ path: tempDir, json: true }));

      await program.parseAsync(['node', 'test', 'quarantine', '--path', tempDir, '--json']);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.filesQuarantined.length).toBe(1);
    });

    it('should handle nested directory structures in quarantine', async () => {
      const deepDir = path.join(tempDir, 'a', 'b', 'c');
      fs.mkdirSync(deepDir, { recursive: true });
      fs.writeFileSync(path.join(deepDir, 'deep-malware.php'), '<?php eval($cmd); ?>');

      const program = createProgram();
      registerQuarantineCommand(program, createTestCliOptions({ path: tempDir, json: true, force: true }));

      await program.parseAsync(['node', 'test', 'quarantine', '--path', tempDir, '--force', '--json']);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.success).toBe(true);
      expect(fs.existsSync(path.join(deepDir, 'deep-malware.php'))).toBe(false);

      const quarantinedFile = path.join(result.quarantineDir, 'a', 'b', 'c', 'deep-malware.php');
      expect(fs.existsSync(quarantinedFile)).toBe(true);
    });
  });
});
