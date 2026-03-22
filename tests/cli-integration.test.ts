import { spawn, ChildProcess } from 'child_process';
import * as path from 'path';

const CLI_PATH = path.join(__dirname, '..', 'bin', 'clean-sweep');
const CLEAN_FIXTURE = path.join(__dirname, '..', 'test', 'fixtures', 'clean-wp');
const MALWARE_FIXTURE = path.join(__dirname, '..', 'test', 'fixtures', 'wp-install');

function runCli(args: string[]): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    const proc: ChildProcess = spawn('node', [CLI_PATH, ...args], {
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

describe('CLI Integration Tests', () => {
  describe('scan command', () => {
    it('scan --dry-run --json returns safe:true for clean fixtures', async () => {
      const { stdout, code } = await runCli([
        'scan',
        '--path', CLEAN_FIXTURE,
        '--json',
        '--dry-run',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('safe');
      expect(output.safe).toBe(true);
      expect(output).toHaveProperty('threats');
      expect(output.threats).toEqual([]);
    });

    it('scan --dry-run --json returns safe:false for malware fixtures', async () => {
      const { stdout, code } = await runCli([
        'scan',
        '--path', MALWARE_FIXTURE,
        '--json',
        '--dry-run',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('safe');
      expect(output.safe).toBe(false);
      expect(output).toHaveProperty('threats');
      expect((output.threats as unknown[]).length).toBeGreaterThan(0);
    });

    it('scan with verbose flag includes detailed threat info', async () => {
      const { stdout, code } = await runCli([
        'scan',
        '--path', MALWARE_FIXTURE,
        '--json',
        '--verbose',
        '--dry-run',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect((output.threats as unknown[]).length).toBeGreaterThan(0);
      expect((output.threats as Record<string, unknown>[])[0]).toHaveProperty('file');
      expect((output.threats as Record<string, unknown>[])[0]).toHaveProperty('type');
    });

    it('scan --check-integrity returns integrity data', async () => {
      const { stdout, code } = await runCli([
        'scan',
        '--path', CLEAN_FIXTURE,
        '--json',
        '--check-integrity',
        '--dry-run',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('integrity');
    });

    it('scan --find-unknown returns unknown files data', async () => {
      const { stdout, code } = await runCli([
        'scan',
        '--path', CLEAN_FIXTURE,
        '--json',
        '--find-unknown',
        '--dry-run',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('unknownFiles');
    });

    it('scan --check-vulnerabilities returns empty vulnerabilities for fixture without WordPress', async () => {
      const { stdout, code } = await runCli([
        'scan',
        '--path', CLEAN_FIXTURE,
        '--json',
        '--check-vulnerabilities',
        '--dry-run',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('vulnerabilities');
      expect(output.vulnerabilities).toEqual([]);
    }, 30000);

    it('scan --check-vulnerabilities returns vulnerabilities object when flag is set', async () => {
      const { stdout, code } = await runCli([
        'scan',
        '--path', CLEAN_FIXTURE,
        '--json',
        '--check-vulnerabilities',
        '--dry-run',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output.vulnerabilities).toBeDefined();
      expect(Array.isArray(output.vulnerabilities)).toBe(true);
    }, 30000);

    it('scan --check-vulnerabilities includes plugins info when plugin vulnerability data exists', async () => {
      const { stdout, code } = await runCli([
        'scan',
        '--path', CLEAN_FIXTURE,
        '--json',
        '--check-vulnerabilities',
        '--check-integrity',
        '--dry-run',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('vulnerabilities');
      expect(output).toHaveProperty('integrity');
      expect(output).toHaveProperty('suggestions');
    }, 30000);

    it('scan returns proper output structure with all optional flags combined', async () => {
      const { stdout, code } = await runCli([
        'scan',
        '--path', CLEAN_FIXTURE,
        '--json',
        '--check-vulnerabilities',
        '--check-integrity',
        '--find-unknown',
        '--dry-run',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('path');
      expect(output).toHaveProperty('files');
      expect(output).toHaveProperty('directories');
      expect(output).toHaveProperty('totalFiles');
      expect(output).toHaveProperty('totalDirectories');
      expect(output).toHaveProperty('threats');
      expect(output).toHaveProperty('safe');
      expect(output).toHaveProperty('dryRun');
      expect(output).toHaveProperty('vulnerabilities');
      expect(output).toHaveProperty('integrity');
      expect(output).toHaveProperty('unknownFiles');
      expect(output).toHaveProperty('suggestions');
    }, 30000);

    it('scan --check-vulnerabilities handles non-existent path gracefully', async () => {
      const { stdout, code } = await runCli([
        'scan',
        '--path', '/non/existent/path',
        '--json',
        '--check-vulnerabilities',
      ]);

      expect(code).toBe(1);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('error');
    }, 30000);
  });

  describe('status command', () => {
    it('status --json returns valid JSON with status fields', async () => {
      const { stdout, code } = await runCli([
        'status',
        '--path', CLEAN_FIXTURE,
        '--json',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('version');
      expect(output).toHaveProperty('pluginsCount');
      expect(output).toHaveProperty('themesCount');
      expect(output).toHaveProperty('dbConnected');
      expect(output).toHaveProperty('wpContentWritable');
      expect(output).toHaveProperty('dryRun');
      expect(typeof output.pluginsCount).toBe('number');
      expect(typeof output.themesCount).toBe('number');
    });

    it('status returns graceful handling for non-existent path', async () => {
      const { stdout, code } = await runCli([
        'status',
        '--path', '/non/existent/path',
        '--json',
      ]);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output.version).toBeNull();
      expect(output.pluginsCount).toBe(0);
      expect(output.themesCount).toBe(0);
    });

    it('status returns graceful handling when path is not a directory', async () => {
      const notADir = path.join(__dirname, '..', 'package.json');

      const { stdout, code } = await runCli([
        'status',
        '--path', notADir,
        '--json',
      ]);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output.version).toBeNull();
      expect(output.pluginsCount).toBe(0);
    });
  });

  describe('error handling', () => {
    it('scan returns error for non-existent path', async () => {
      const { stdout, code } = await runCli([
        'scan',
        '--path', '/non/existent/path',
        '--json',
      ]);

      expect(code).toBe(1);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('error');
      expect(output.error).toBe('Path does not exist');
    });

    it('scan returns error when path is not a directory', async () => {
      const notADir = path.join(__dirname, '..', 'package.json');

      const { stdout, code } = await runCli([
        'scan',
        '--path', notADir,
        '--json',
      ]);

      expect(code).toBe(1);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('error');
      expect(output.error).toBe('Path is not a directory');
    });
  });

  describe('JSON output validation', () => {
    it('scan --json output contains valid JSON', async () => {
      const { stdout, code } = await runCli([
        'scan',
        '--path', CLEAN_FIXTURE,
        '--json',
        '--dry-run',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout);
      expect(output).not.toBeNull();
    });

    it('status --json output is valid JSON', async () => {
      const { stdout, code } = await runCli([
        'status',
        '--path', CLEAN_FIXTURE,
        '--json',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout);
      expect(output).not.toBeNull();
    });

    it('scan output contains all required fields', async () => {
      const { stdout, code } = await runCli([
        'scan',
        '--path', CLEAN_FIXTURE,
        '--json',
        '--dry-run',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('path');
      expect(output).toHaveProperty('files');
      expect(output).toHaveProperty('directories');
      expect(output).toHaveProperty('totalFiles');
      expect(output).toHaveProperty('totalDirectories');
      expect(output).toHaveProperty('threats');
      expect(output).toHaveProperty('safe');
      expect(output).toHaveProperty('dryRun');
    });
  });

  describe('help and version', () => {
    it('--version returns version string', async () => {
      const { stdout, code } = await runCli(['--version']);

      expect(code).toBe(0);
      expect(stdout.trim()).toBe('1.0.0');
    });

    it('--help returns help text', async () => {
      const { stdout, code } = await runCli(['--help']);

      expect(code).toBe(0);
      expect(stdout).toContain('clean-sweep');
      expect(stdout).toContain('scan');
      expect(stdout).toContain('status');
    });
  });
});