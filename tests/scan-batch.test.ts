import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { spawn } from 'child_process';

const CLI_PATH = path.join(__dirname, '..', 'bin', 'clean-sweep');
const CLEAN_FIXTURE = path.join(__dirname, '..', 'test', 'fixtures', 'clean-wp');
const MALWARE_FIXTURE = path.join(__dirname, '..', 'test', 'fixtures', 'wp-install');

function runCli(args: string[]): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    const proc = spawn('node', [CLI_PATH, ...args], {
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    proc.stdout?.on('data', (data: Buffer) => {
      stdout += data.toString();
    });

    proc.stderr?.on('data', (data: Buffer) => {
      stderr += data.toString();
    });

    proc.on('close', (code) => {
      resolve({ stdout, stderr, code: code ?? 0 });
    });
  });
}

function extractLastJson(str: string): unknown {
  const lines = str.split('\n');
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i].trim();
    if (line.startsWith('{') && line.endsWith('}')) {
      try {
        return JSON.parse(line);
      } catch {
        continue;
      }
    }
    const remaining = lines.slice(i).join('\n').trim();
    if (remaining.startsWith('{')) {
      try {
        return JSON.parse(remaining);
      } catch {
        continue;
      }
    }
  }
  try {
    return JSON.parse(str);
  } catch {
    return null;
  }
}

describe('scan:batch command', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-batch-test-'));
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('error handling', () => {
    it('returns error when --list-file is not provided', async () => {
      const { stdout, code } = await runCli([
        'scan:batch',
        '--json',
      ]);

      expect(code).toBe(1);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('error');
      expect(output.error).toContain('List file is required');
    });

    it('returns error when list file does not exist', async () => {
      const { stdout, code } = await runCli([
        'scan:batch',
        '--list-file', '/non/existent/file.txt',
        '--json',
      ]);

      expect(code).toBe(1);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('error');
      expect((output.error as string)).toContain('List file does not exist');
    });

    it('returns error when list file is empty', async () => {
      const listFile = path.join(tempDir, 'empty.txt');
      fs.writeFileSync(listFile, '');

      const { stdout, code } = await runCli([
        'scan:batch',
        '--list-file', listFile,
        '--json',
      ]);

      expect(code).toBe(1);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('error');
      expect((output.error as string)).toContain('empty');
    });

    it('returns error when list file has only comments', async () => {
      const listFile = path.join(tempDir, 'comments-only.txt');
      fs.writeFileSync(listFile, '# comment line\n# another comment\n');

      const { stdout, code } = await runCli([
        'scan:batch',
        '--list-file', listFile,
        '--json',
      ]);

      expect(code).toBe(1);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('error');
      expect((output.error as string)).toContain('empty');
    });
  });

  describe('batch scanning', () => {
    it('scans a single clean directory and reports safe', async () => {
      const listFile = path.join(tempDir, 'dirs.txt');
      fs.writeFileSync(listFile, CLEAN_FIXTURE + '\n');

      const { stdout, code } = await runCli([
        'scan:batch',
        '--list-file', listFile,
        '--json',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('timestamp');
      expect(output).toHaveProperty('directories');
      expect(output).toHaveProperty('totalDirectories');
      expect(output).toHaveProperty('totalFiles');
      expect(output).toHaveProperty('totalThreats');
      expect(output).toHaveProperty('overallSafe');
      expect(output.totalDirectories).toBe(1);
      expect(output.totalThreats).toBe(0);
      expect(output.overallSafe).toBe(true);
      expect(Array.isArray(output.directories)).toBe(true);
      expect((output.directories as unknown[]).length).toBe(1);
    });

    it('scans a malware directory and reports unsafe', async () => {
      const listFile = path.join(tempDir, 'dirs.txt');
      fs.writeFileSync(listFile, MALWARE_FIXTURE + '\n');

      const { stdout, code } = await runCli([
        'scan:batch',
        '--list-file', listFile,
        '--json',
      ]);

      expect(code).toBe(2);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output.totalDirectories).toBe(1);
      expect((output.totalThreats as number)).toBeGreaterThan(0);
      expect(output.overallSafe).toBe(false);
      expect(output.unsafeDirectories).toBe(1);
      expect(output.safeDirectories).toBe(0);
    });

    it('scans multiple directories and produces combined report', async () => {
      const listFile = path.join(tempDir, 'dirs.txt');
      fs.writeFileSync(listFile, `${CLEAN_FIXTURE}\n${MALWARE_FIXTURE}\n`);

      const { stdout, code } = await runCli([
        'scan:batch',
        '--list-file', listFile,
        '--json',
      ]);

      expect(code).toBe(2);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output.totalDirectories).toBe(2);
      expect((output.totalThreats as number)).toBeGreaterThan(0);
      expect(output.overallSafe).toBe(false);
      expect(output.safeDirectories).toBe(1);
      expect(output.unsafeDirectories).toBe(1);
    });

    it('skips non-existent directories and reports errors', async () => {
      const listFile = path.join(tempDir, 'dirs.txt');
      fs.writeFileSync(listFile, `${CLEAN_FIXTURE}\n/non/existent/path\n`);

      const { stdout, code } = await runCli([
        'scan:batch',
        '--list-file', listFile,
        '--json',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output.totalDirectories).toBe(1);
      expect(output).toHaveProperty('errors');
      expect(Array.isArray(output.errors)).toBe(true);
      expect((output.errors as unknown[]).length).toBe(1);
      const err = (output.errors as Record<string, unknown>[])[0];
      expect(err.path).toContain('non');
      expect(err.error).toContain('does not exist');
    });

    it('skips file paths that are not directories', async () => {
      const listFile = path.join(tempDir, 'dirs.txt');
      fs.writeFileSync(listFile, `${CLEAN_FIXTURE}\n${path.join(__dirname, '..', 'package.json')}\n`);

      const { stdout, code } = await runCli([
        'scan:batch',
        '--list-file', listFile,
        '--json',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output.totalDirectories).toBe(1);
      expect(output).toHaveProperty('errors');
      expect((output.errors as unknown[]).length).toBe(1);
      const err = (output.errors as Record<string, unknown>[])[0];
      expect(err.error).toContain('not a directory');
    });
  });

  describe('JSON output', () => {
    it('produces valid JSON output', async () => {
      const listFile = path.join(tempDir, 'dirs.txt');
      fs.writeFileSync(listFile, CLEAN_FIXTURE + '\n');

      const { stdout, code } = await runCli([
        'scan:batch',
        '--list-file', listFile,
        '--json',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout);
      expect(output).not.toBeNull();
      expect(() => JSON.stringify(output)).not.toThrow();
    });

    it('JSON output contains all required fields', async () => {
      const listFile = path.join(tempDir, 'dirs.txt');
      fs.writeFileSync(listFile, CLEAN_FIXTURE + '\n');

      const { stdout, code } = await runCli([
        'scan:batch',
        '--list-file', listFile,
        '--json',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(typeof output.timestamp).toBe('string');
      expect(Array.isArray(output.directories)).toBe(true);
      expect(typeof output.totalDirectories).toBe('number');
      expect(typeof output.totalFiles).toBe('number');
      expect(typeof output.totalThreats).toBe('number');
      expect(typeof output.totalWhitelisted).toBe('number');
      expect(typeof output.safeDirectories).toBe('number');
      expect(typeof output.unsafeDirectories).toBe('number');
      expect(typeof output.overallSafe).toBe('boolean');
    });

    it('each directory result has correct structure', async () => {
      const listFile = path.join(tempDir, 'dirs.txt');
      fs.writeFileSync(listFile, CLEAN_FIXTURE + '\n');

      const { stdout, code } = await runCli([
        'scan:batch',
        '--list-file', listFile,
        '--json',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      const dir = (output.directories as Record<string, unknown>[])[0];
      expect(typeof dir.path).toBe('string');
      expect(typeof dir.totalFiles).toBe('number');
      expect(typeof dir.totalDirectories).toBe('number');
      expect(Array.isArray(dir.threats)).toBe(true);
      expect(typeof dir.safe).toBe('boolean');
      expect(typeof dir.whitelisted).toBe('number');
    });
  });

  describe('text output', () => {
    it('produces text output when --json is not used', async () => {
      const listFile = path.join(tempDir, 'dirs.txt');
      fs.writeFileSync(listFile, CLEAN_FIXTURE + '\n');

      const { stdout, code } = await runCli([
        'scan:batch',
        '--list-file', listFile,
      ]);

      expect(code).toBe(0);
      expect(stdout).toContain('SAFE');
      expect(stdout).toContain('Batch scan complete');
      expect(stdout).toContain('Overall result');
    });

    it('text output shows UNSAFE for malware directory', async () => {
      const listFile = path.join(tempDir, 'dirs.txt');
      fs.writeFileSync(listFile, MALWARE_FIXTURE + '\n');

      const { stdout, code } = await runCli([
        'scan:batch',
        '--list-file', listFile,
      ]);

      expect(code).toBe(2);
      expect(stdout).toContain('UNSAFE');
    });
  });

  describe('list file parsing', () => {
    it('handles comment lines in list file', async () => {
      const listFile = path.join(tempDir, 'dirs.txt');
      fs.writeFileSync(listFile, `# This is a comment\n${CLEAN_FIXTURE}\n# Another comment\n`);

      const { stdout, code } = await runCli([
        'scan:batch',
        '--list-file', listFile,
        '--json',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output.totalDirectories).toBe(1);
    });

    it('handles blank lines in list file', async () => {
      const listFile = path.join(tempDir, 'dirs.txt');
      fs.writeFileSync(listFile, `\n${CLEAN_FIXTURE}\n\n${MALWARE_FIXTURE}\n\n`);

      const { stdout, code } = await runCli([
        'scan:batch',
        '--list-file', listFile,
        '--json',
      ]);

      expect(code).toBe(2);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output.totalDirectories).toBe(2);
    });
  });

  describe('help', () => {
    it('scan:batch --help shows help text', async () => {
      const { stdout, code } = await runCli(['scan:batch', '--help']);

      expect(code).toBe(0);
      expect(stdout).toContain('scan:batch');
      expect(stdout).toContain('--list-file');
    });
  });
});
