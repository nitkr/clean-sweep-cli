import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { Command } from 'commander';
import { registerRestoreCommand } from '../src/commands/restore';

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

function createQuarantineStructure(
  tempDir: string,
  folderName: string,
  files: Record<string, string>
): string {
  const quarantineDir = path.join(tempDir, 'quarantine', folderName);
  fs.mkdirSync(quarantineDir, { recursive: true });

  for (const [relativePath, content] of Object.entries(files)) {
    const fullPath = path.join(quarantineDir, relativePath);
    const dir = path.dirname(fullPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(fullPath, content);
  }

  return quarantineDir;
}

describe('Restore Command', () => {
  let tempDir: string;
  let consoleSpy: jest.SpyInstance;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'restore-test-'));
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

  describe('listing quarantine folders', () => {
    it('should show no quarantine folders when none exist', async () => {
      const program = createProgram();
      registerRestoreCommand(program, createTestCliOptions({ path: tempDir, json: true }));

      await program.parseAsync(['node', 'test', 'restore', '--path', tempDir, '--json']);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      const result = JSON.parse(output);
      expect(result.success).toBe(true);
      expect(result.quarantineFolders).toEqual([]);
      expect(result.selectedFolder).toBeNull();
    });

    it('should list available quarantine folders', async () => {
      createQuarantineStructure(tempDir, '2024-01-15T10-00-00', {
        'malware.php': '<?php eval($cmd); ?>',
      });
      createQuarantineStructure(tempDir, '2024-01-16T10-00-00', {
        'evil.js': 'eval("alert(1)")',
      });

      const program = createProgram();
      registerRestoreCommand(program, createTestCliOptions({ path: tempDir, json: true }));

      await program.parseAsync(['node', 'test', 'restore', '--path', tempDir, '--json']);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      const result = JSON.parse(output);
      expect(result.success).toBe(true);
      expect(result.quarantineFolders.length).toBe(2);
      expect(result.quarantineFolders[0].name).toBe('2024-01-15T10-00-00');
      expect(result.quarantineFolders[1].name).toBe('2024-01-16T10-00-00');
      expect(result.quarantineFolders[0].files).toContain('malware.php');
      expect(result.quarantineFolders[1].files).toContain('evil.js');
    });

    it('should show file count per folder in human-readable output', async () => {
      createQuarantineStructure(tempDir, '2024-01-15T10-00-00', {
        'file1.php': 'a',
        'file2.php': 'b',
      });

      const program = createProgram();
      registerRestoreCommand(program, createTestCliOptions({ path: tempDir, json: false }));

      await program.parseAsync(['node', 'test', 'restore', '--path', tempDir]);

      const allOutput = consoleSpy.mock.calls.map(c => String(c[0])).join('\n');
      expect(allOutput).toContain('Available quarantine folders');
      expect(allOutput).toContain('2024-01-15T10-00-00');
      expect(allOutput).toContain('2 file(s)');
    });

    it('should list files preserving nested directory structure', async () => {
      createQuarantineStructure(tempDir, '2024-01-15T10-00-00', {
        'wp-content/plugins/evil/evil.php': '<?php eval($cmd); ?>',
      });

      const program = createProgram();
      registerRestoreCommand(program, createTestCliOptions({ path: tempDir, json: true }));

      await program.parseAsync(['node', 'test', 'restore', '--path', tempDir, '--json']);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      const result = JSON.parse(output);
      expect(result.quarantineFolders[0].files).toContain(
        'wp-content/plugins/evil/evil.php'
      );
    });
  });

  describe('dry-run mode (default)', () => {
    it('should preview restore without moving files', async () => {
      createQuarantineStructure(tempDir, '2024-01-15T10-00-00', {
        'malware.php': '<?php eval($cmd); ?>',
      });

      const program = createProgram();
      registerRestoreCommand(program, createTestCliOptions({ path: tempDir, json: true }));

      await program.parseAsync([
        'node', 'test', 'restore', '--path', tempDir,
        '--folder', '2024-01-15T10-00-00', '--json',
      ]);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      const result = JSON.parse(output);
      expect(result.success).toBe(true);
      expect(result.dryRun).toBe(true);
      expect(result.selectedFolder).toBe('2024-01-15T10-00-00');
      expect(result.filesRestored).toContain('malware.php');

      expect(fs.existsSync(path.join(tempDir, 'malware.php'))).toBe(false);
    });

    it('should show human-readable dry-run output', async () => {
      createQuarantineStructure(tempDir, '2024-01-15T10-00-00', {
        'malware.php': '<?php eval($cmd); ?>',
      });

      const program = createProgram();
      registerRestoreCommand(program, createTestCliOptions({ path: tempDir, json: false }));

      await program.parseAsync([
        'node', 'test', 'restore', '--path', tempDir,
        '--folder', '2024-01-15T10-00-00',
      ]);

      const allOutput = consoleSpy.mock.calls.map(c => String(c[0])).join('\n');
      expect(allOutput).toContain('Would restore');
      expect(allOutput).toContain('malware.php');
      expect(allOutput).toContain('Dry run mode');
    });
  });

  describe('force mode', () => {
    it('should restore files to original locations with --force', async () => {
      createQuarantineStructure(tempDir, '2024-01-15T10-00-00', {
        'malware.php': '<?php eval($cmd); ?>',
      });

      const program = createProgram();
      registerRestoreCommand(program, createTestCliOptions({ path: tempDir, json: true, force: true }));

      await program.parseAsync([
        'node', 'test', 'restore', '--path', tempDir,
        '--folder', '2024-01-15T10-00-00', '--force', '--json',
      ]);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.success).toBe(true);
      expect(result.dryRun).toBe(false);
      expect(result.filesRestored).toContain('malware.php');
      expect(fs.existsSync(path.join(tempDir, 'malware.php'))).toBe(true);
    });

    it('should restore files preserving directory structure', async () => {
      createQuarantineStructure(tempDir, '2024-01-15T10-00-00', {
        'wp-content/plugins/evil/evil.php': '<?php eval($cmd); ?>',
      });

      const program = createProgram();
      registerRestoreCommand(program, createTestCliOptions({ path: tempDir, json: true, force: true }));

      await program.parseAsync([
        'node', 'test', 'restore', '--path', tempDir,
        '--folder', '2024-01-15T10-00-00', '--force', '--json',
      ]);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.success).toBe(true);
      const restoredFile = path.join(tempDir, 'wp-content', 'plugins', 'evil', 'evil.php');
      expect(fs.existsSync(restoredFile)).toBe(true);
      expect(fs.readFileSync(restoredFile, 'utf-8')).toBe('<?php eval($cmd); ?>');
    });

    it('should restore multiple files', async () => {
      createQuarantineStructure(tempDir, '2024-01-15T10-00-00', {
        'file1.php': 'content1',
        'file2.js': 'content2',
        'subdir/file3.php': 'content3',
      });

      const program = createProgram();
      registerRestoreCommand(program, createTestCliOptions({ path: tempDir, json: true, force: true }));

      await program.parseAsync([
        'node', 'test', 'restore', '--path', tempDir,
        '--folder', '2024-01-15T10-00-00', '--force', '--json',
      ]);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.success).toBe(true);
      expect(result.filesRestored.length).toBe(3);
      expect(fs.existsSync(path.join(tempDir, 'file1.php'))).toBe(true);
      expect(fs.existsSync(path.join(tempDir, 'file2.js'))).toBe(true);
      expect(fs.existsSync(path.join(tempDir, 'subdir', 'file3.php'))).toBe(true);
    });

    it('should preserve file contents exactly', async () => {
      const originalContent = '<?php echo "original content"; ?>';
      createQuarantineStructure(tempDir, '2024-01-15T10-00-00', {
        'test.php': originalContent,
      });

      const program = createProgram();
      registerRestoreCommand(program, createTestCliOptions({ path: tempDir, json: true, force: true }));

      await program.parseAsync([
        'node', 'test', 'restore', '--path', tempDir,
        '--folder', '2024-01-15T10-00-00', '--force', '--json',
      ]);

      const restoredContent = fs.readFileSync(path.join(tempDir, 'test.php'), 'utf-8');
      expect(restoredContent).toBe(originalContent);
    });
  });

  describe('JSON output', () => {
    it('should output valid JSON with --json flag', async () => {
      createQuarantineStructure(tempDir, '2024-01-15T10-00-00', {
        'malware.php': 'x',
      });

      const program = createProgram();
      registerRestoreCommand(program, createTestCliOptions({ path: tempDir, json: true }));

      await program.parseAsync([
        'node', 'test', 'restore', '--path', tempDir,
        '--folder', '2024-01-15T10-00-00', '--json',
      ]);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      expect(() => JSON.parse(output)).not.toThrow();
    });

    it('should include all expected fields in JSON output', async () => {
      const program = createProgram();
      registerRestoreCommand(program, createTestCliOptions({ path: tempDir, json: true }));

      await program.parseAsync(['node', 'test', 'restore', '--path', tempDir, '--json']);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      const result = JSON.parse(output);

      expect(result).toHaveProperty('success');
      expect(result).toHaveProperty('dryRun');
      expect(result).toHaveProperty('quarantineFolders');
      expect(result).toHaveProperty('selectedFolder');
      expect(result).toHaveProperty('filesRestored');
      expect(result).toHaveProperty('errors');
    });
  });

  describe('error handling', () => {
    it('should fail for non-existent path', async () => {
      const program = createProgram();
      registerRestoreCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'restore', '--path', '/nonexistent/path/12345', '--json',
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
      registerRestoreCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync(['node', 'test', 'restore', '--path', filePath, '--json']);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      expect(mockExit).toHaveBeenCalledWith(1);
      mockExit.mockRestore();
    });

    it('should fail for non-existent quarantine folder', async () => {
      createQuarantineStructure(tempDir, '2024-01-15T10-00-00', {
        'malware.php': 'x',
      });

      const program = createProgram();
      registerRestoreCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'restore', '--path', tempDir,
          '--folder', 'nonexistent-folder', '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      expect(mockExit).toHaveBeenCalledWith(1);
      mockExit.mockRestore();
    });
  });

  describe('edge cases', () => {
    it('should ignore non-directory entries in quarantine folder', async () => {
      const quarantineBase = path.join(tempDir, 'quarantine');
      fs.mkdirSync(quarantineBase, { recursive: true });
      fs.writeFileSync(path.join(quarantineBase, 'not-a-dir.txt'), 'content');
      createQuarantineStructure(tempDir, '2024-01-15T10-00-00', {
        'malware.php': 'x',
      });

      const program = createProgram();
      registerRestoreCommand(program, createTestCliOptions({ path: tempDir, json: true }));

      await program.parseAsync(['node', 'test', 'restore', '--path', tempDir, '--json']);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      const result = JSON.parse(output);
      expect(result.quarantineFolders.length).toBe(1);
      expect(result.quarantineFolders[0].name).toBe('2024-01-15T10-00-00');
    });

    it('should handle empty quarantine folder', async () => {
      createQuarantineStructure(tempDir, '2024-01-15T10-00-00', {});

      const program = createProgram();
      registerRestoreCommand(program, createTestCliOptions({ path: tempDir, json: true }));

      await program.parseAsync([
        'node', 'test', 'restore', '--path', tempDir,
        '--folder', '2024-01-15T10-00-00', '--force', '--json',
      ]);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      const result = JSON.parse(output);
      expect(result.success).toBe(true);
      expect(result.filesRestored.length).toBe(0);
    });

    it('should sort quarantine folders alphabetically', async () => {
      createQuarantineStructure(tempDir, '2024-03-01T10-00-00', { 'a.php': 'a' });
      createQuarantineStructure(tempDir, '2024-01-15T10-00-00', { 'b.php': 'b' });
      createQuarantineStructure(tempDir, '2024-02-10T10-00-00', { 'c.php': 'c' });

      const program = createProgram();
      registerRestoreCommand(program, createTestCliOptions({ path: tempDir, json: true }));

      await program.parseAsync(['node', 'test', 'restore', '--path', tempDir, '--json']);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('');
      const result = JSON.parse(output);
      expect(result.quarantineFolders[0].name).toBe('2024-01-15T10-00-00');
      expect(result.quarantineFolders[1].name).toBe('2024-02-10T10-00-00');
      expect(result.quarantineFolders[2].name).toBe('2024-03-01T10-00-00');
    });
  });
});
