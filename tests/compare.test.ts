import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { compareScanResults, loadScanResult } from '../src/commands/compare';

describe('Compare Module', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compare-test-'));
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('loadScanResult', () => {
    it('should load a valid scan result JSON file', () => {
      const filePath = path.join(tempDir, 'scan.json');
      const data = {
        path: '/some/path',
        threats: [],
        safe: true,
        files: [],
        directories: [],
        totalFiles: 0,
        totalDirectories: 0,
        dryRun: false,
        whitelisted: 0,
      };
      fs.writeFileSync(filePath, JSON.stringify(data));

      const result = loadScanResult(filePath);
      expect(result.path).toBe('/some/path');
      expect(result.threats).toEqual([]);
      expect(result.safe).toBe(true);
    });

    it('should throw for non-existent file', () => {
      const filePath = path.join(tempDir, 'nonexistent.json');
      expect(() => loadScanResult(filePath)).toThrow('File not found');
    });

    it('should throw for invalid JSON', () => {
      const filePath = path.join(tempDir, 'invalid.json');
      fs.writeFileSync(filePath, 'not json');
      expect(() => loadScanResult(filePath)).toThrow();
    });

    it('should throw when threats array is missing', () => {
      const filePath = path.join(tempDir, 'no-threats.json');
      fs.writeFileSync(filePath, JSON.stringify({ safe: true, path: '/x' }));
      expect(() => loadScanResult(filePath)).toThrow("missing 'threats' array");
    });

    it('should throw when safe boolean is missing', () => {
      const filePath = path.join(tempDir, 'no-safe.json');
      fs.writeFileSync(filePath, JSON.stringify({ threats: [], path: '/x' }));
      expect(() => loadScanResult(filePath)).toThrow("missing 'safe' boolean");
    });
  });

  describe('compareScanResults', () => {
    it('should report unchanged when both scans are clean', () => {
      const baseline = {
        path: '/scan1',
        threats: [],
        safe: true,
        files: ['a.php'],
        directories: [],
        totalFiles: 1,
        totalDirectories: 0,
        dryRun: false,
        whitelisted: 0,
      };
      const current = { ...baseline, path: '/scan2' };

      const result = compareScanResults(baseline, current);

      expect(result.status.unchanged).toBe(true);
      expect(result.status.improved).toBe(false);
      expect(result.status.degraded).toBe(false);
      expect(result.threats.delta).toBe(0);
      expect(result.threats.newThreats).toEqual([]);
      expect(result.threats.resolvedThreats).toEqual([]);
    });

    it('should detect new threats', () => {
      const baseline = {
        path: '/scan1',
        threats: [],
        safe: true,
        files: ['a.php'],
        directories: [],
        totalFiles: 1,
        totalDirectories: 0,
        dryRun: false,
        whitelisted: 0,
      };
      const current = {
        path: '/scan2',
        threats: [
          { file: 'evil.php', type: 'php_eval', line: 10, signature: 'eval(' },
        ],
        safe: false,
        files: ['a.php', 'evil.php'],
        directories: [],
        totalFiles: 2,
        totalDirectories: 0,
        dryRun: false,
        whitelisted: 0,
      };

      const result = compareScanResults(baseline, current);

      expect(result.status.degraded).toBe(true);
      expect(result.threats.delta).toBe(1);
      expect(result.threats.newThreats).toHaveLength(1);
      expect(result.threats.newThreats[0].file).toBe('evil.php');
      expect(result.threats.resolvedThreats).toHaveLength(0);
    });

    it('should detect resolved threats', () => {
      const baseline = {
        path: '/scan1',
        threats: [
          { file: 'evil.php', type: 'php_eval', line: 10, signature: 'eval(' },
          { file: 'shell.php', type: 'php_shell_exec', line: 5, signature: 'shell_exec(' },
        ],
        safe: false,
        files: ['evil.php', 'shell.php'],
        directories: [],
        totalFiles: 2,
        totalDirectories: 0,
        dryRun: false,
        whitelisted: 0,
      };
      const current = {
        path: '/scan2',
        threats: [
          { file: 'evil.php', type: 'php_eval', line: 10, signature: 'eval(' },
        ],
        safe: false,
        files: ['evil.php'],
        directories: [],
        totalFiles: 1,
        totalDirectories: 0,
        dryRun: false,
        whitelisted: 0,
      };

      const result = compareScanResults(baseline, current);

      expect(result.status.improved).toBe(true);
      expect(result.threats.delta).toBe(-1);
      expect(result.threats.newThreats).toHaveLength(0);
      expect(result.threats.resolvedThreats).toHaveLength(1);
      expect(result.threats.resolvedThreats[0].file).toBe('shell.php');
    });

    it('should detect both new and resolved threats', () => {
      const baseline = {
        path: '/scan1',
        threats: [
          { file: 'old.php', type: 'php_eval', line: 1, signature: 'eval(' },
        ],
        safe: false,
        files: ['old.php'],
        directories: [],
        totalFiles: 1,
        totalDirectories: 0,
        dryRun: false,
        whitelisted: 0,
      };
      const current = {
        path: '/scan2',
        threats: [
          { file: 'new.php', type: 'php_base64_decode', line: 2, signature: 'base64_decode(' },
        ],
        safe: false,
        files: ['new.php'],
        directories: [],
        totalFiles: 1,
        totalDirectories: 0,
        dryRun: false,
        whitelisted: 0,
      };

      const result = compareScanResults(baseline, current);

      expect(result.status.unchanged).toBe(true);
      expect(result.threats.delta).toBe(0);
      expect(result.threats.newThreats).toHaveLength(1);
      expect(result.threats.newThreats[0].file).toBe('new.php');
      expect(result.threats.resolvedThreats).toHaveLength(1);
      expect(result.threats.resolvedThreats[0].file).toBe('old.php');
    });

    it('should compute threat deltas by type', () => {
      const baseline = {
        path: '/scan1',
        threats: [
          { file: 'a.php', type: 'php_eval', line: null, signature: 'eval(' },
          { file: 'b.php', type: 'php_eval', line: null, signature: 'eval(' },
          { file: 'c.php', type: 'php_system', line: null, signature: 'system(' },
        ],
        safe: false,
        files: ['a.php', 'b.php', 'c.php'],
        directories: [],
        totalFiles: 3,
        totalDirectories: 0,
        dryRun: false,
        whitelisted: 0,
      };
      const current = {
        path: '/scan2',
        threats: [
          { file: 'a.php', type: 'php_eval', line: null, signature: 'eval(' },
          { file: 'd.php', type: 'php_base64_decode', line: null, signature: 'base64_decode(' },
        ],
        safe: false,
        files: ['a.php', 'd.php'],
        directories: [],
        totalFiles: 2,
        totalDirectories: 0,
        dryRun: false,
        whitelisted: 0,
      };

      const result = compareScanResults(baseline, current);

      const evalDelta = result.threats.byType.find(d => d.type === 'php_eval');
      const systemDelta = result.threats.byType.find(d => d.type === 'php_system');
      const base64Delta = result.threats.byType.find(d => d.type === 'php_base64_decode');

      expect(evalDelta).toEqual({ type: 'php_eval', before: 2, after: 1, change: -1 });
      expect(systemDelta).toEqual({ type: 'php_system', before: 1, after: 0, change: -1 });
      expect(base64Delta).toEqual({ type: 'php_base64_decode', before: 0, after: 1, change: 1 });
    });

    it('should detect file changes', () => {
      const baseline = {
        path: '/scan1',
        threats: [],
        safe: true,
        files: ['a.php', 'b.php'],
        directories: [],
        totalFiles: 2,
        totalDirectories: 0,
        dryRun: false,
        whitelisted: 0,
      };
      const current = {
        path: '/scan2',
        threats: [],
        safe: true,
        files: ['a.php', 'c.php'],
        directories: [],
        totalFiles: 2,
        totalDirectories: 0,
        dryRun: false,
        whitelisted: 0,
      };

      const result = compareScanResults(baseline, current);

      expect(result.files.delta).toBe(0);
      expect(result.files.newFiles).toEqual(['c.php']);
      expect(result.files.removedFiles).toEqual(['b.php']);
    });

    it('should handle missing files arrays gracefully', () => {
      const baseline = {
        path: '/scan1',
        threats: [],
        safe: true,
      };
      const current = {
        path: '/scan2',
        threats: [],
        safe: true,
      };

      const result = compareScanResults(baseline as any, current as any);

      expect(result.files.baseline).toBe(0);
      expect(result.files.current).toBe(0);
      expect(result.files.delta).toBe(0);
    });

    it('should compare vulnerabilities when present', () => {
      const baseline = {
        path: '/scan1',
        threats: [],
        safe: true,
        files: [],
        directories: [],
        totalFiles: 0,
        totalDirectories: 0,
        dryRun: false,
        whitelisted: 0,
        vulnerabilities: [
          { component: 'WordPress', version: '6.0', cve: 'CVE-2023-0001', title: 'XSS', severity: 'high' },
          { component: 'akismet', version: '5.0', cve: 'CVE-2023-0002', title: 'SQLi', severity: 'critical' },
        ],
      };
      const current = {
        path: '/scan2',
        threats: [],
        safe: true,
        files: [],
        directories: [],
        totalFiles: 0,
        totalDirectories: 0,
        dryRun: false,
        whitelisted: 0,
        vulnerabilities: [
          { component: 'WordPress', version: '6.0', cve: 'CVE-2023-0001', title: 'XSS', severity: 'high' },
          { component: 'hello-dolly', version: '1.0', cve: 'CVE-2023-0003', title: 'CSRF', severity: 'medium' },
        ],
      };

      const result = compareScanResults(baseline, current);

      expect(result.vulnerabilities).toBeDefined();
      expect(result.vulnerabilities!.baseline).toBe(2);
      expect(result.vulnerabilities!.current).toBe(2);
      expect(result.vulnerabilities!.delta).toBe(0);
      expect(result.vulnerabilities!.newVulnerabilities).toHaveLength(1);
      expect(result.vulnerabilities!.newVulnerabilities[0].cve).toBe('CVE-2023-0003');
      expect(result.vulnerabilities!.resolvedVulnerabilities).toHaveLength(1);
      expect(result.vulnerabilities!.resolvedVulnerabilities[0].cve).toBe('CVE-2023-0002');
    });

    it('should not include vulnerabilities section when neither scan has them', () => {
      const baseline = {
        path: '/scan1',
        threats: [],
        safe: true,
        files: [],
        directories: [],
        totalFiles: 0,
        totalDirectories: 0,
        dryRun: false,
        whitelisted: 0,
      };
      const current = {
        path: '/scan2',
        threats: [],
        safe: true,
        files: [],
        directories: [],
        totalFiles: 0,
        totalDirectories: 0,
        dryRun: false,
        whitelisted: 0,
      };

      const result = compareScanResults(baseline, current);

      expect(result.vulnerabilities).toBeUndefined();
    });

    it('should compare integrity results when present', () => {
      const baseline = {
        path: '/scan1',
        threats: [],
        safe: true,
        files: [],
        directories: [],
        totalFiles: 0,
        totalDirectories: 0,
        dryRun: false,
        whitelisted: 0,
        integrity: { checked: 100, modified: 2, modifiedFiles: ['wp-login.php', 'wp-config.php'] },
      };
      const current = {
        path: '/scan2',
        threats: [],
        safe: true,
        files: [],
        directories: [],
        totalFiles: 0,
        totalDirectories: 0,
        dryRun: false,
        whitelisted: 0,
        integrity: { checked: 100, modified: 3, modifiedFiles: ['wp-login.php', 'wp-config.php', 'index.php'] },
      };

      const result = compareScanResults(baseline, current);

      expect(result.integrity).toBeDefined();
      expect(result.integrity!.baselineModified).toBe(2);
      expect(result.integrity!.currentModified).toBe(3);
      expect(result.integrity!.delta).toBe(1);
      expect(result.integrity!.newModified).toEqual(['index.php']);
      expect(result.integrity!.resolvedModified).toEqual([]);
    });

    it('should detect restored integrity files', () => {
      const baseline = {
        path: '/scan1',
        threats: [],
        safe: true,
        files: [],
        directories: [],
        totalFiles: 0,
        totalDirectories: 0,
        dryRun: false,
        whitelisted: 0,
        integrity: { checked: 100, modified: 2, modifiedFiles: ['wp-login.php', 'index.php'] },
      };
      const current = {
        path: '/scan2',
        threats: [],
        safe: true,
        files: [],
        directories: [],
        totalFiles: 0,
        totalDirectories: 0,
        dryRun: false,
        whitelisted: 0,
        integrity: { checked: 100, modified: 1, modifiedFiles: ['wp-login.php'] },
      };

      const result = compareScanResults(baseline, current);

      expect(result.integrity!.delta).toBe(-1);
      expect(result.integrity!.newModified).toEqual([]);
      expect(result.integrity!.resolvedModified).toEqual(['index.php']);
    });

    it('should use baseline path from baseline and current path from current', () => {
      const baseline = {
        path: '/baseline/path',
        threats: [],
        safe: true,
        files: [],
        directories: [],
        totalFiles: 0,
        totalDirectories: 0,
        dryRun: false,
        whitelisted: 0,
      };
      const current = {
        path: '/current/path',
        threats: [],
        safe: true,
        files: [],
        directories: [],
        totalFiles: 0,
        totalDirectories: 0,
        dryRun: false,
        whitelisted: 0,
      };

      const result = compareScanResults(baseline, current);

      expect(result.baseline.path).toBe('/baseline/path');
      expect(result.current.path).toBe('/current/path');
    });

    it('should sort type deltas by absolute change descending', () => {
      const baseline = {
        path: '/scan1',
        threats: [
          { file: 'a.php', type: 'php_eval', line: null, signature: 'eval(' },
          { file: 'b.php', type: 'php_system', line: null, signature: 'system(' },
          { file: 'c.php', type: 'php_system', line: null, signature: 'system(' },
          { file: 'd.php', type: 'php_system', line: null, signature: 'system(' },
        ],
        safe: false,
        files: ['a.php', 'b.php', 'c.php', 'd.php'],
        directories: [],
        totalFiles: 4,
        totalDirectories: 0,
        dryRun: false,
        whitelisted: 0,
      };
      const current = {
        path: '/scan2',
        threats: [],
        safe: true,
        files: [],
        directories: [],
        totalFiles: 0,
        totalDirectories: 0,
        dryRun: false,
        whitelisted: 0,
      };

      const result = compareScanResults(baseline, current);

      expect(result.threats.byType[0].type).toBe('php_system');
      expect(result.threats.byType[0].change).toBe(-3);
      expect(result.threats.byType[1].type).toBe('php_eval');
      expect(result.threats.byType[1].change).toBe(-1);
    });
  });
});
