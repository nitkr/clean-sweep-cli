import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { Command } from 'commander';

jest.mock('node-fetch', () => ({
  __esModule: true,
  default: jest.fn(),
}));

import fetch from 'node-fetch';
const mockFetch = fetch as any;

import { registerDepsCheckCommand } from '../src/commands/deps-check';

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

describe('Deps Check Command', () => {
  let tempDir: string;
  let consoleSpy: ReturnType<typeof jest.spyOn>;
  let consoleErrorSpy: ReturnType<typeof jest.spyOn>;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'deps-check-test-'));
    consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    mockFetch.mockClear();
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
      registerDepsCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'deps:check',
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
      registerDepsCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'deps:check',
          '--path', filePath,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      expect(mockExit).toHaveBeenCalledWith(1);
      mockExit.mockRestore();
    });

    it('should fail when no dependency files found', async () => {
      const program = createProgram();
      registerDepsCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'deps:check',
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

  describe('package.json parsing', () => {
    it('should detect package.json and list dependencies', async () => {
      const pkg = {
        name: 'test-project',
        version: '1.0.0',
        dependencies: {
          'lodash': '^4.17.21',
        },
        devDependencies: {
          'jest': '^29.0.0',
        },
      };
      fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkg));

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ vulnerabilities: [] }),
      });

      const program = createProgram();
      registerDepsCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'deps:check',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.filesFound).toContain('package.json');
      expect(result.totalDependencies).toBe(2);
      expect(result.hasVulnerabilities).toBe(false);
      mockExit.mockRestore();
    });
  });

  describe('composer.json parsing', () => {
    it('should detect composer.json and list dependencies', async () => {
      const composer = {
        require: {
          'php': '^8.1',
          'symfony/console': '^6.0',
          'guzzlehttp/guzzle': '^7.0',
        },
        'require-dev': {
          'phpunit/phpunit': '^10.0',
        },
      };
      fs.writeFileSync(path.join(tempDir, 'composer.json'), JSON.stringify(composer));

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ vulnerabilities: [] }),
      });

      const program = createProgram();
      registerDepsCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'deps:check',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.filesFound).toContain('composer.json');
      expect(result.totalDependencies).toBe(3);
      expect(result.vulnerabilities).toBeDefined();
      mockExit.mockRestore();
    });

    it('should skip php and ext- dependencies from composer.json', async () => {
      const composer = {
        require: {
          'php': '^8.1',
          'ext-mbstring': '*',
          'symfony/console': '^6.0',
        },
      };
      fs.writeFileSync(path.join(tempDir, 'composer.json'), JSON.stringify(composer));

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ vulnerabilities: [] }),
      });

      const program = createProgram();
      registerDepsCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'deps:check',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.totalDependencies).toBe(1);
      mockExit.mockRestore();
    });
  });

  describe('both files present', () => {
    it('should parse both package.json and composer.json', async () => {
      const pkg = {
        dependencies: { 'express': '^4.18.0' },
      };
      const composer = {
        require: { 'symfony/console': '^6.0' },
      };
      fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkg));
      fs.writeFileSync(path.join(tempDir, 'composer.json'), JSON.stringify(composer));

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ vulnerabilities: [] }),
      });

      const program = createProgram();
      registerDepsCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'deps:check',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.filesFound).toContain('package.json');
      expect(result.filesFound).toContain('composer.json');
      expect(result.totalDependencies).toBe(2);
      mockExit.mockRestore();
    });
  });

  describe('vulnerability detection', () => {
    it('should report vulnerabilities found via OSV API', async () => {
      const pkg = {
        dependencies: { 'lodash': '^4.17.0' },
      };
      fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkg));

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          vulnerabilities: [
            {
              id: 'CVE-2021-23337',
              summary: 'Prototype Pollution in lodash',
              severity: [{ type: 'CVSS_V3', score: '7.2' }],
              references: [{ type: 'ADVISORY', url: 'https://example.com/vuln/1' }],
            },
          ],
        }),
      });

      const program = createProgram();
      registerDepsCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'deps:check',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.hasVulnerabilities).toBe(true);
      expect(result.vulnerabilities).toHaveLength(1);
      expect(result.vulnerabilities[0].name).toBe('lodash');
      expect(result.vulnerabilities[0].severity).toBe('HIGH');
      expect(result.vulnerabilities[0].cve).toBe('CVE-2021-23337');
      mockExit.mockRestore();
    });

    it('should handle API fetch errors gracefully', async () => {
      const pkg = {
        dependencies: { 'lodash': '^4.17.21' },
      };
      fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkg));

      mockFetch.mockRejectedValue(new Error('Network error'));

      const program = createProgram();
      registerDepsCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'deps:check',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.totalDependencies).toBe(1);
      expect(result.hasVulnerabilities).toBe(false);
      mockExit.mockRestore();
    });

    it('should handle non-OK API responses', async () => {
      const pkg = {
        dependencies: { 'lodash': '^4.17.21' },
      };
      fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkg));

      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
      });

      const program = createProgram();
      registerDepsCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'deps:check',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.hasVulnerabilities).toBe(false);
      mockExit.mockRestore();
    });
  });

  describe('severity classification', () => {
    it('should classify CRITICAL for CVSS >= 9.0', async () => {
      const pkg = {
        dependencies: { 'crit-pkg': '^1.0.0' },
      };
      fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkg));

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          vulnerabilities: [
            {
              id: 'CVE-TEST',
              summary: 'Critical vuln',
              severity: [{ type: 'CVSS_V3', score: '9.8' }],
            },
          ],
        }),
      });

      const program = createProgram();
      registerDepsCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'deps:check',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.vulnerabilities[0].severity).toBe('CRITICAL');
      mockExit.mockRestore();
    });

    it('should classify MEDIUM for CVSS >= 4.0 and < 7.0', async () => {
      const pkg = {
        dependencies: { 'med-pkg': '^1.0.0' },
      };
      fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkg));

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          vulnerabilities: [
            {
              id: 'CVE-TEST',
              summary: 'Medium vuln',
              severity: [{ type: 'CVSS_V3', score: '5.0' }],
            },
          ],
        }),
      });

      const program = createProgram();
      registerDepsCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'deps:check',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.vulnerabilities[0].severity).toBe('MEDIUM');
      mockExit.mockRestore();
    });

    it('should classify LOW for CVSS < 4.0', async () => {
      const pkg = {
        dependencies: { 'low-pkg': '^1.0.0' },
      };
      fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkg));

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          vulnerabilities: [
            {
              id: 'CVE-TEST',
              summary: 'Low vuln',
              severity: [{ type: 'CVSS_V3', score: '2.1' }],
            },
          ],
        }),
      });

      const program = createProgram();
      registerDepsCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'deps:check',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.vulnerabilities[0].severity).toBe('LOW');
      mockExit.mockRestore();
    });
  });

  describe('severity filter', () => {
    it('should filter vulns by severity', async () => {
      const pkg = {
        dependencies: { 'mixed-pkg': '^1.0.0' },
      };
      fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkg));

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          vulnerabilities: [
            {
              id: 'CVE-HIGH',
              summary: 'High vuln',
              severity: [{ type: 'CVSS_V3', score: '8.0' }],
            },
            {
              id: 'CVE-LOW',
              summary: 'Low vuln',
              severity: [{ type: 'CVSS_V3', score: '2.0' }],
            },
          ],
        }),
      });

      const program = createProgram();
      registerDepsCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'deps:check',
          '--path', tempDir,
          '--severity', 'HIGH',
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.vulnerabilities).toHaveLength(1);
      expect(result.vulnerabilities[0].severity).toBe('HIGH');
      mockExit.mockRestore();
    });

    it('should accept severity flag without error', async () => {
      const pkg = {
        dependencies: { 'lodash': '^4.17.21' },
      };
      fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkg));

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ vulnerabilities: [] }),
      });

      const program = createProgram();
      registerDepsCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'deps:check',
          '--path', tempDir,
          '--severity', 'high',
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);

      expect(result).toHaveProperty('vulnerabilities');
      mockExit.mockRestore();
    });
  });

  describe('JSON output format', () => {
    it('should produce valid JSON with all expected fields', async () => {
      const pkg = {
        dependencies: { 'lodash': '^4.17.21' },
      };
      fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkg));

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ vulnerabilities: [] }),
      });

      const program = createProgram();
      registerDepsCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'deps:check',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);

      expect(result).toHaveProperty('path');
      expect(result).toHaveProperty('filesFound');
      expect(result).toHaveProperty('totalDependencies');
      expect(result).toHaveProperty('vulnerabilities');
      expect(result).toHaveProperty('hasVulnerabilities');
      expect(result).toHaveProperty('bySeverity');
      mockExit.mockRestore();
    });

    it('should produce valid JSON for error case', async () => {
      const program = createProgram();
      registerDepsCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'deps:check',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      // The error output is a JSON object on console.log
      const logCalls = consoleSpy.mock.calls.map((c: any) => String(c[0]));
      const jsonCalls = logCalls.filter((s: string) => s.trim().startsWith('{'));
      for (const call of jsonCalls) {
        expect(() => JSON.parse(call)).not.toThrow();
      }
      expect(mockExit).toHaveBeenCalledWith(1);
      mockExit.mockRestore();
    });
  });

  describe('human-readable output', () => {
    it('should print dependency info without --json', async () => {
      const pkg = {
        dependencies: { 'lodash': '^4.17.21' },
      };
      fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkg));

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ vulnerabilities: [] }),
      });

      const program = createProgram();
      registerDepsCheckCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'deps:check',
          '--path', tempDir,
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const allOutput = consoleSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('Checking dependencies');
      expect(allOutput).toContain('Dependency files found');
      expect(allOutput).toContain('package.json');
      expect(allOutput).toContain('Total dependencies');
      mockExit.mockRestore();
    });

    it('should print vulnerabilities in human-readable output', async () => {
      const pkg = {
        dependencies: { 'lodash': '^4.17.0' },
      };
      fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkg));

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          vulnerabilities: [
            {
              id: 'CVE-2021-1234',
              summary: 'Test vuln',
              severity: [{ type: 'CVSS_V3', score: '7.0' }],
              references: [{ type: 'ADVISORY', url: 'https://example.com' }],
            },
          ],
        }),
      });

      const program = createProgram();
      registerDepsCheckCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'deps:check',
          '--path', tempDir,
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const allOutput = consoleSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('Found');
      expect(allOutput).toContain('vulnerability');
      expect(allOutput).toContain('lodash');
      expect(allOutput).toContain('Severity breakdown');
      mockExit.mockRestore();
    });

    it('should print human-readable error for non-existent path', async () => {
      const program = createProgram();
      registerDepsCheckCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'deps:check',
          '--path', '/nonexistent/path/12345',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const allOutput = consoleErrorSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('Path does not exist');
      mockExit.mockRestore();
    });
  });

  describe('exit codes', () => {
    it('should exit 0 when no vulnerabilities found', async () => {
      const pkg = {
        dependencies: { 'lodash': '^4.17.21' },
      };
      fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkg));

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ vulnerabilities: [] }),
      });

      const program = createProgram();
      registerDepsCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'deps:check',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      expect(mockExit).toHaveBeenCalledWith(0);
      mockExit.mockRestore();
    });

    it('should exit 1 when vulnerabilities found', async () => {
      const pkg = {
        dependencies: { 'lodash': '^4.17.0' },
      };
      fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkg));

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          vulnerabilities: [
            {
              id: 'CVE-TEST',
              summary: 'Test vuln',
              severity: [{ type: 'CVSS_V3', score: '8.0' }],
            },
          ],
        }),
      });

      const program = createProgram();
      registerDepsCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'deps:check',
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
});
