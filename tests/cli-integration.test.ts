import { spawn, ChildProcess } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';

const CLI_PATH = path.join(__dirname, '..', 'bin', 'clean-sweep');
const CLEAN_FIXTURE = path.join(__dirname, '..', 'test', 'fixtures', 'clean-wp');
const MALWARE_FIXTURE = path.join(__dirname, '..', 'test', 'fixtures', 'wp-install');
const WP_COMPLETE_FIXTURE = path.join(__dirname, '..', 'test', 'fixtures', 'wp-complete');
const WP_EMPTY_FIXTURE = path.join(__dirname, '..', 'test', 'fixtures', 'wp-empty');
const TEST_ZIP_FIXTURE = path.join(__dirname, '..', 'test', 'fixtures', 'test-zip', 'files.zip');
const NON_WP_FIXTURE = path.join(__dirname, '..', 'test', 'fixtures', 'non-wp-dir');

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

    it('status returns error for non-existent path', async () => {
      const { stdout, code } = await runCli([
        'status',
        '--path', '/non/existent/path',
        '--json',
      ]);

      expect(code).toBe(1);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('error');
      expect(output.error).toBe('Path does not exist');
    });

    it('status returns graceful handling when path is not a directory', async () => {
      const notADir = path.join(__dirname, '..', 'package.json');

      const { stdout, code } = await runCli([
        'status',
        '--path', notADir,
        '--json',
      ]);

      expect(code).toBe(1);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('error');
      expect(output.error).toBe('Path is not a directory');
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

  describe('verbose flag', () => {
    it('scan --verbose flag produces detailed output', async () => {
      const { stdout, code } = await runCli([
        'scan',
        '--path', MALWARE_FIXTURE,
        '--verbose',
        '--json',
        '--dry-run',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect((output.threats as unknown[]).length).toBeGreaterThan(0);

      const firstThreat = (output.threats as Record<string, unknown>[])[0];
      expect(firstThreat).toHaveProperty('file');
      expect(firstThreat).toHaveProperty('type');
    });

    it('scan without --verbose still returns threats but may have less detail', async () => {
      const { stdout, code } = await runCli([
        'scan',
        '--path', MALWARE_FIXTURE,
        '--json',
        '--dry-run',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect((output.threats as unknown[]).length).toBeGreaterThan(0);
    });

    it('status --verbose flag works', async () => {
      const { stdout, code } = await runCli([
        'status',
        '--path', CLEAN_FIXTURE,
        '--verbose',
        '--json',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('version');
    });
  });

  describe('scan output field validation', () => {
    it('scan output has correct field types for clean fixture', async () => {
      const { stdout, code } = await runCli([
        'scan',
        '--path', CLEAN_FIXTURE,
        '--json',
        '--dry-run',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(typeof output.path).toBe('string');
      expect(Array.isArray(output.files)).toBe(true);
      expect(Array.isArray(output.directories)).toBe(true);
      expect(typeof output.totalFiles).toBe('number');
      expect(typeof output.totalDirectories).toBe('number');
      expect(typeof output.safe).toBe('boolean');
      expect(Array.isArray(output.threats)).toBe(true);
    });

    it('scan output has correct field types for malware fixture', async () => {
      const { stdout, code } = await runCli([
        'scan',
        '--path', MALWARE_FIXTURE,
        '--json',
        '--dry-run',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(typeof output.path).toBe('string');
      expect(output.safe).toBe(false);
      expect(Array.isArray(output.threats)).toBe(true);
      expect((output.threats as unknown[]).length).toBeGreaterThan(0);

      const firstThreat = (output.threats as Record<string, unknown>[])[0];
      expect(typeof firstThreat.file).toBe('string');
      expect(typeof firstThreat.type).toBe('string');
    });

    it('scan output path matches scanned path', async () => {
      const { stdout, code } = await runCli([
        'scan',
        '--path', CLEAN_FIXTURE,
        '--json',
        '--dry-run',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output.path).toContain('clean-wp');
    });
  });

  describe('status output field validation', () => {
    it('status output has correct field types', async () => {
      const { stdout, code } = await runCli([
        'status',
        '--path', CLEAN_FIXTURE,
        '--json',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output.version === null || typeof output.version === 'string').toBe(true);
      expect(typeof output.pluginsCount).toBe('number');
      expect(typeof output.themesCount).toBe('number');
      expect(typeof output.dbConnected).toBe('boolean');
      expect(typeof output.wpContentWritable).toBe('boolean');
      expect(typeof output.dryRun).toBe('boolean');
    });
  });

  describe('JSON parseability validation', () => {
    it('scan --json output can be parsed with JSON.parse directly', async () => {
      const { stdout, code } = await runCli([
        'scan',
        '--path', CLEAN_FIXTURE,
        '--json',
        '--dry-run',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout);
      expect(output).not.toBeNull();
      expect(() => JSON.stringify(output)).not.toThrow();
    });

    it('status --json output can be parsed with JSON.parse directly', async () => {
      const { stdout, code } = await runCli([
        'status',
        '--path', CLEAN_FIXTURE,
        '--json',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout);
      expect(output).not.toBeNull();
      expect(() => JSON.stringify(output)).not.toThrow();
    });

    it('both --json and non-json output works', async () => {
      const jsonResult = await runCli([
        'scan',
        '--path', CLEAN_FIXTURE,
        '--json',
        '--dry-run',
      ]);

      const textResult = await runCli([
        'scan',
        '--path', CLEAN_FIXTURE,
        '--dry-run',
      ]);

      expect(jsonResult.code).toBe(0);
      expect(textResult.code).toBe(0);
      expect(textResult.stdout).toContain('safe');
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

  describe('db:scan error handling', () => {
    it('returns error when wp-config.php is missing and no db params provided', async () => {
      const { stdout, code } = await runCli([
        'db:scan',
        '--path', CLEAN_FIXTURE,
        '--json',
      ]);

      expect(code).toBe(1);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('success');
      expect(output.success).toBe(false);
      expect(output.error).toContain('wp-config.php');
    });

    it('returns error when database credentials are incomplete', async () => {
      const { stdout, code } = await runCli([
        'db:scan',
        '--path', CLEAN_FIXTURE,
        '--db-host', 'localhost',
        '--json',
      ]);

      expect(code).toBe(1);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('success');
      expect(output.success).toBe(false);
    });

    it('succeeds with database parameters provided in dry-run mode', async () => {
      const { stdout, code } = await runCli([
        'db:scan',
        '--path', CLEAN_FIXTURE,
        '--db-host', 'localhost',
        '--db-name', 'testdb',
        '--db-user', 'testuser',
        '--json',
        '--dry-run',
      ]);

      expect(code).toBe(0);
      expect(stdout).toContain('"success": true');
    }, 30000);
  });

  describe('db:scan dry-run and json format', () => {
    it('db:scan --dry-run outputs expected dry-run format in text mode', async () => {
      const { stdout, code } = await runCli([
        'db:scan',
        '--path', CLEAN_FIXTURE,
        '--db-host', 'localhost',
        '--db-name', 'testdb',
        '--db-user', 'testuser',
        '--dry-run',
      ]);

      expect(code).toBe(0);
      expect(stdout).toContain('[DRY RUN]');
      expect(stdout).toContain('Would scan table:');
      expect(stdout).toContain('wp_posts');
    }, 30000);

    it('db:scan --json outputs valid JSON format', async () => {
      const { stdout, code } = await runCli([
        'db:scan',
        '--path', CLEAN_FIXTURE,
        '--db-host', 'localhost',
        '--db-name', 'testdb',
        '--db-user', 'testuser',
        '--json',
        '--dry-run',
      ]);

      expect(code).toBe(0);

      const jsonMatch = stdout.match(/\{[\s\S]*"success":\s*true[\s\S]*\}/g);
      expect(jsonMatch).not.toBeNull();
      
      const output = JSON.parse(jsonMatch![0]) as Record<string, unknown>;
      expect(output).toHaveProperty('success');
      expect(output.success).toBe(true);
      expect(output).toHaveProperty('scannedTables');
      expect(Array.isArray(output.scannedTables)).toBe(true);
      expect((output.scannedTables as string[]).length).toBeGreaterThan(0);
      expect(output).toHaveProperty('threats');
      expect(Array.isArray(output.threats)).toBe(true);
      expect(output).toHaveProperty('dryRun');
      expect(output.dryRun).toBe(true);
    }, 30000);

    it('db:scan returns error for non-WP directory without wp-config.php', async () => {
      const { stdout, code } = await runCli([
        'db:scan',
        '--path', CLEAN_FIXTURE,
        '--json',
      ]);

      expect(code).toBe(1);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('success');
      expect(output.success).toBe(false);
      expect(output).toHaveProperty('error');
      expect(output.error).toContain('wp-config.php');
    });
  });

  describe('file:extract error handling', () => {
    it('returns error when zip path is not provided', async () => {
      const { stdout, code } = await runCli([
        'file:extract',
        '--path', CLEAN_FIXTURE,
        '--json',
      ]);

      expect(code).toBe(1);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('error');
      expect(output.error).toContain('ZIP');
    });

    it('returns error when WordPress path does not exist', async () => {
      const { stdout, code } = await runCli([
        'file:extract',
        '--path', '/non/existent/path',
        '--zip', '/some/file.zip',
        '--json',
      ]);

      expect(code).toBe(1);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('error');
      expect(output.error).toContain('does not exist');
    });

    it('returns error when ZIP file does not exist', async () => {
      const { stdout, code } = await runCli([
        'file:extract',
        '--path', WP_COMPLETE_FIXTURE,
        '--zip', '/non/existent/file.zip',
        '--json',
      ]);

      expect(code).toBe(1);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('error');
      expect(output.error).toContain('does not exist');
    });

    it('file:extract --dry-run outputs expected dry-run format in text mode', async () => {
      const { stdout, code } = await runCli([
        'file:extract',
        '--path', WP_COMPLETE_FIXTURE,
        '--zip', TEST_ZIP_FIXTURE,
        '--dry-run',
      ]);

      expect(code).toBe(0);
      expect(stdout).toContain('[DRY RUN]');
      expect(stdout).toContain('Would extract ZIP:');
      expect(stdout).toContain('Would extract');
      expect(stdout).toContain('file(s):');
    });

    it('file:extract --json outputs valid JSON format', async () => {
      const { stdout, code } = await runCli([
        'file:extract',
        '--path', WP_COMPLETE_FIXTURE,
        '--zip', TEST_ZIP_FIXTURE,
        '--json',
        '--dry-run',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('success');
      expect(output.success).toBe(true);
      expect(output).toHaveProperty('extractedFiles');
      expect(Array.isArray(output.extractedFiles)).toBe(true);
      expect(output).toHaveProperty('dryRun');
      expect(output.dryRun).toBe(true);
    });

    it('file:extract returns error for non-existent ZIP file', async () => {
      const { stdout, code } = await runCli([
        'file:extract',
        '--path', WP_COMPLETE_FIXTURE,
        '--zip', '/path/to/nonexistent.zip',
        '--json',
      ]);

      expect(code).toBe(1);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('success');
      expect(output.success).toBe(false);
      expect(output).toHaveProperty('error');
      expect(output.error).toContain('does not exist');
    });

    it('file:extract returns error for non-WP directory', async () => {
      const { stdout, code } = await runCli([
        'file:extract',
        '--path', NON_WP_FIXTURE,
        '--zip', TEST_ZIP_FIXTURE,
        '--json',
      ]);

      expect(code).toBe(1);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('success');
      expect(output.success).toBe(false);
      expect(output).toHaveProperty('error');
    });
  });

  describe('plugin:reinstall error handling', () => {
    it('returns error when plugin slug is not provided', async () => {
      const { stdout, code } = await runCli([
        'plugin:reinstall',
        '--path', CLEAN_FIXTURE,
        '--json',
      ]);

      expect(code).toBe(1);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('error');
      expect(output.error).toContain('Plugin slug');
    });

    it('returns error for invalid plugin slug', async () => {
      const { stdout, code } = await runCli([
        'plugin:reinstall',
        '--path', CLEAN_FIXTURE,
        '--plugin', 'nonexistent-plugin-slug-12345',
        '--json',
        '--dry-run',
      ]);

      expect(code).toBe(1);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('success');
      expect(output.success).toBe(false);
    }, 30000);
  });

  describe('core:repair error handling', () => {
    it('returns error when path does not exist', async () => {
      const { stdout, code } = await runCli([
        'core:repair',
        '--path', '/non/existent/path',
        '--json',
      ]);

      expect(code).toBe(1);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('error');
    });

    it('returns error when path is not a directory', async () => {
      const notADir = path.join(__dirname, '..', 'package.json');

      const { stdout, code } = await runCli([
        'core:repair',
        '--path', notADir,
        '--json',
      ]);

      expect(code).toBe(1);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('error');
    });

    it('returns error for non-WP directory', async () => {
      const { stdout, code } = await runCli([
        'core:repair',
        '--path', NON_WP_FIXTURE,
        '--json',
        '--dry-run',
      ]);

      expect(code).toBe(1);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('error');
    }, 30000);
  });

  describe('core:repair --dry-run', () => {
    it('shows files to replace and preserve in output', async () => {
      const { stdout, code } = await runCli([
        'core:repair',
        '--path', CLEAN_FIXTURE,
        '--dry-run',
      ]);

      expect(code).toBe(0);
      expect(stdout).toContain('[DRY RUN] Would replace');
      expect(stdout).toContain('[DRY RUN] Would preserve');
    }, 30000);
  });

  describe('core:repair --json', () => {
    it('returns valid JSON with expected properties', async () => {
      const { stdout, code } = await runCli([
        'core:repair',
        '--path', CLEAN_FIXTURE,
        '--json',
        '--dry-run',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('success');
      expect(output.success).toBe(true);
      expect(output).toHaveProperty('filesReplaced');
      expect(output).toHaveProperty('filesPreserved');
      expect(output).toHaveProperty('dryRun');
      expect(output.dryRun).toBe(true);
    }, 30000);
  });

  describe('cleanup error handling', () => {
    it('returns error and exits when --force is not provided', async () => {
      const { stdout, code } = await runCli([
        'cleanup',
        '--path', CLEAN_FIXTURE,
        '--json',
      ]);

      expect(code).toBe(1);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('error');
      expect(output.error).toContain('--force');
    });

    it('returns error when path does not exist', async () => {
      const { stdout, code } = await runCli([
        'cleanup',
        '--path', '/non/existent/path',
        '--force',
        '--json',
      ]);

      expect(code).toBe(1);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('error');
      expect(output.error).toBe('Path does not exist');
    });

    it('returns success when --force is provided', async () => {
      const { stdout, code } = await runCli([
        'cleanup',
        '--path', CLEAN_FIXTURE,
        '--force',
        '--json',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('success');
      expect(output.success).toBe(true);
    });
  });

  describe('wp-complete fixture tests', () => {
    it('scan on wp-complete fixture returns safe:true', async () => {
      const { stdout, code } = await runCli([
        'scan',
        '--path', WP_COMPLETE_FIXTURE,
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

    it('status on wp-complete fixture detects WP version, plugins, themes', async () => {
      const { stdout, code } = await runCli([
        'status',
        '--path', WP_COMPLETE_FIXTURE,
        '--json',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('version');
      expect(output.version).toBe('6.4.2');
      expect(output).toHaveProperty('pluginsCount');
      expect(output.pluginsCount).toBeGreaterThan(0);
      expect(output).toHaveProperty('themesCount');
      expect(output.themesCount).toBeGreaterThan(0);
    });
  });

  describe('wp-empty fixture tests', () => {
    it('scan on wp-empty fixture returns safe:true', async () => {
      const { stdout, code } = await runCli([
        'scan',
        '--path', WP_EMPTY_FIXTURE,
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
  });

  describe('large directory performance tests', () => {
    const TEST_FILE_COUNT = 100;
    let tempDir: string;

    beforeAll(() => {
      tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'clean-sweep-perf-'));
      const phpContent = `<?php
/**
 * Test file for performance testing
 */
class TestClass {
    public function test() {
        return true;
    }
}
`;

      for (let i = 0; i < TEST_FILE_COUNT; i++) {
        const filePath = path.join(tempDir, `test-file-${i}.php`);
        fs.writeFileSync(filePath, phpContent);
      }
    });

    afterAll(() => {
      if (tempDir && fs.existsSync(tempDir)) {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });

    it('scans large directory within reasonable time', async () => {
      const startTime = Date.now();

      const { stdout, code } = await runCli([
        'scan',
        '--path', tempDir,
        '--json',
        '--dry-run',
      ]);

      const endTime = Date.now();
      const duration = endTime - startTime;

      expect(code).toBe(0);
      expect(duration).toBeLessThan(30000);
    }, 60000);

    it('correctly identifies clean files in large directory', async () => {
      const { stdout, code } = await runCli([
        'scan',
        '--path', tempDir,
        '--json',
        '--dry-run',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('safe');
      expect(output.safe).toBe(true);
      expect(output).toHaveProperty('threats');
      expect(output.threats).toEqual([]);
      expect(output).toHaveProperty('totalFiles');
      expect((output.totalFiles as number)).toBeGreaterThanOrEqual(TEST_FILE_COUNT);
    }, 60000);

    it('scan with verbose flag includes details for large directory', async () => {
      const { stdout, code } = await runCli([
        'scan',
        '--path', tempDir,
        '--json',
        '--verbose',
        '--dry-run',
      ]);

      expect(code).toBe(0);

      const output = extractLastJson(stdout) as Record<string, unknown>;
      expect(output).toHaveProperty('files');
      expect(Array.isArray(output.files)).toBe(true);
      expect((output.files as unknown[]).length).toBeGreaterThanOrEqual(TEST_FILE_COUNT);
    }, 60000);
  });
});