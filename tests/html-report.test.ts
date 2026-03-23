import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  generateHtmlReport,
  saveHtmlReport,
  getDefaultHtmlReportPath,
  HtmlReportData,
} from '../src/html-report';
import { ScanResult, Threat } from '../src/malware-scanner';
import { Vulnerability } from '../src/vulnerability-scanner';
import { IntegrityResult } from '../src/file-integrity';

function createMockScanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    path: '/test/path',
    files: ['/test/path/file.php'],
    directories: ['/test/path/subdir'],
    totalFiles: 10,
    totalDirectories: 2,
    threats: [],
    safe: true,
    dryRun: false,
    whitelisted: 0,
    ...overrides,
  };
}

function createMockThreat(overrides: Partial<Threat> = {}): Threat {
  return {
    file: '/test/path/malicious.php',
    type: 'php_eval',
    line: 5,
    signature: 'eval(',
    ...overrides,
  };
}

describe('HTML Report Module', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'html-report-test-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('generateHtmlReport', () => {
    it('should return a valid HTML string', () => {
      const data: HtmlReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
        suggestions: [],
      };
      const html = generateHtmlReport(data);
      expect(html).toContain('<!DOCTYPE html>');
      expect(html).toContain('<html');
      expect(html).toContain('</html>');
    });

    it('should include the scan path', () => {
      const data: HtmlReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/var/www/wordpress',
        scanResult: createMockScanResult(),
        suggestions: [],
      };
      const html = generateHtmlReport(data);
      expect(html).toContain('/var/www/wordpress');
    });

    it('should include the timestamp', () => {
      const data: HtmlReportData = {
        timestamp: '2024-01-15T10:30:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
        suggestions: [],
      };
      const html = generateHtmlReport(data);
      expect(html).toContain('2024');
    });

    it('should display SAFE status when no threats found', () => {
      const data: HtmlReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ safe: true, threats: [] }),
        suggestions: [],
      };
      const html = generateHtmlReport(data);
      expect(html).toContain('SAFE');
      expect(html).toContain('No threats detected');
    });

    it('should display UNSAFE status when threats found', () => {
      const threat = createMockThreat();
      const data: HtmlReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ safe: false, threats: [threat] }),
        suggestions: [],
      };
      const html = generateHtmlReport(data);
      expect(html).toContain('THREATS DETECTED');
    });

    it('should display threat details in a table', () => {
      const threats: Threat[] = [
        createMockThreat({ file: '/test/path/backdoor.php', type: 'php_eval', line: 10, signature: 'eval(' }),
        createMockThreat({ file: '/test/path/shell.php', type: 'php_shell_exec', line: null, signature: 'shell_exec(' }),
      ];
      const data: HtmlReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ safe: false, threats }),
        suggestions: [],
      };
      const html = generateHtmlReport(data);
      expect(html).toContain('/test/path/backdoor.php');
      expect(html).toContain('/test/path/shell.php');
      expect(html).toContain('php_eval');
      expect(html).toContain('php_shell_exec');
    });

    it('should display severity levels for threats', () => {
      const threats: Threat[] = [
        createMockThreat({ type: 'php_shell_exec' }),
        createMockThreat({ type: 'php_eval' }),
        createMockThreat({ type: 'base64_large' }),
        createMockThreat({ type: 'php_get_parameter' }),
      ];
      const data: HtmlReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ safe: false, threats }),
        suggestions: [],
      };
      const html = generateHtmlReport(data);
      expect(html).toContain('critical');
      expect(html).toContain('high');
      expect(html).toContain('medium');
      expect(html).toContain('low');
    });

    it('should include file count in summary stats', () => {
      const data: HtmlReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ totalFiles: 42 }),
        suggestions: [],
      };
      const html = generateHtmlReport(data);
      expect(html).toContain('42');
    });

    it('should display line numbers when available', () => {
      const threat = createMockThreat({ line: 42 });
      const data: HtmlReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ safe: false, threats: [threat] }),
        suggestions: [],
      };
      const html = generateHtmlReport(data);
      expect(html).toContain(':42');
    });

    it('should not display line number when null', () => {
      const threat = createMockThreat({ line: null });
      const data: HtmlReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ safe: false, threats: [threat] }),
        suggestions: [],
      };
      const html = generateHtmlReport(data);
      expect(html).not.toMatch(/:null/);
    });

    it('should display suggestions when provided', () => {
      const data: HtmlReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
        suggestions: ['Remove malicious files', 'Update WordPress'],
      };
      const html = generateHtmlReport(data);
      expect(html).toContain('Remove malicious files');
      expect(html).toContain('Update WordPress');
      expect(html).toContain('Recommendations');
    });

    it('should not display suggestions section when empty', () => {
      const data: HtmlReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
        suggestions: [],
      };
      const html = generateHtmlReport(data);
      expect(html).not.toContain('Recommendations');
    });

    it('should display vulnerabilities when provided', () => {
      const vulnerabilities: Vulnerability[] = [
        {
          component: 'wordpress',
          version: '6.0',
          cve: 'CVE-2024-1234',
          title: 'SQL Injection',
          severity: 'high',
        },
      ];
      const data: HtmlReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
        vulnerabilities,
        suggestions: [],
      };
      const html = generateHtmlReport(data);
      expect(html).toContain('Known Vulnerabilities');
      expect(html).toContain('wordpress');
      expect(html).toContain('CVE-2024-1234');
      expect(html).toContain('SQL Injection');
    });

    it('should display integrity results when provided', () => {
      const integrity: IntegrityResult = {
        checked: 100,
        modified: 2,
        modifiedFiles: ['wp-login.php', 'wp-config.php'],
        wordpressVersion: '6.3',
      };
      const data: HtmlReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
        integrity,
        suggestions: [],
      };
      const html = generateHtmlReport(data);
      expect(html).toContain('File Integrity Check');
      expect(html).toContain('6.3');
      expect(html).toContain('wp-login.php');
      expect(html).toContain('wp-config.php');
    });

    it('should escape HTML special characters in scan path', () => {
      const data: HtmlReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/<script>alert("xss")</script>',
        scanResult: createMockScanResult(),
        suggestions: [],
      };
      const html = generateHtmlReport(data);
      expect(html).not.toContain('<script>alert("xss")</script>');
      expect(html).toContain('&lt;script&gt;');
    });

    it('should escape HTML in threat signatures', () => {
      const threat = createMockThreat({
        signature: 'eval("<script>alert(1)</script>")',
      });
      const data: HtmlReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ safe: false, threats: [threat] }),
        suggestions: [],
      };
      const html = generateHtmlReport(data);
      expect(html).not.toContain('<script>alert(1)</script>');
      expect(html).toContain('&lt;script&gt;');
    });

    it('should escape HTML in suggestions', () => {
      const data: HtmlReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
        suggestions: ['Remove <b>bold</b> file'],
      };
      const html = generateHtmlReport(data);
      expect(html).not.toContain('<b>bold</b>');
      expect(html).toContain('&lt;b&gt;');
    });

    it('should handle empty threats array', () => {
      const data: HtmlReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ threats: [], totalFiles: 5 }),
        suggestions: [],
      };
      const html = generateHtmlReport(data);
      expect(html).toContain('No threats detected');
      expect(html).toContain('SAFE');
    });

    it('should handle multiple threats of same type', () => {
      const threats: Threat[] = [
        createMockThreat({ file: '/test/a.php', type: 'php_eval', line: 1 }),
        createMockThreat({ file: '/test/b.php', type: 'php_eval', line: 2 }),
        createMockThreat({ file: '/test/c.php', type: 'php_eval', line: 3 }),
      ];
      const data: HtmlReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ safe: false, threats }),
        suggestions: [],
      };
      const html = generateHtmlReport(data);
      expect(html).toContain('/test/a.php');
      expect(html).toContain('/test/b.php');
      expect(html).toContain('/test/c.php');
    });

    it('should include threat count in header', () => {
      const threats: Threat[] = [
        createMockThreat({ file: '/test/a.php' }),
        createMockThreat({ file: '/test/b.php' }),
      ];
      const data: HtmlReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ safe: false, threats }),
        suggestions: [],
      };
      const html = generateHtmlReport(data);
      expect(html).toContain('Threats Found (2)');
    });

    it('should include footer with timestamp', () => {
      const data: HtmlReportData = {
        timestamp: '2024-06-15T14:30:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
        suggestions: [],
      };
      const html = generateHtmlReport(data);
      expect(html).toContain('Clean Sweep CLI');
    });
  });

  describe('getDefaultHtmlReportPath', () => {
    it('should return a valid path string', () => {
      const reportPath = getDefaultHtmlReportPath('/test/path');
      expect(typeof reportPath).toBe('string');
      expect(reportPath.length).toBeGreaterThan(0);
    });

    it('should include reports directory', () => {
      const reportPath = getDefaultHtmlReportPath('/test/path');
      expect(reportPath.startsWith('reports')).toBe(true);
    });

    it('should include .html extension', () => {
      const reportPath = getDefaultHtmlReportPath('/test/path');
      expect(reportPath.endsWith('.html')).toBe(true);
    });

    it('should include scan prefix', () => {
      const reportPath = getDefaultHtmlReportPath('/test/path');
      expect(reportPath.includes('scan-')).toBe(true);
    });

    it('should include timestamp in the path', () => {
      const reportPath = getDefaultHtmlReportPath('/test/path');
      const hasTimestamp = reportPath.match(/\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}/);
      expect(hasTimestamp).not.toBeNull();
    });

    it('should handle special characters in scanPath', () => {
      const reportPath = getDefaultHtmlReportPath('/test/path with spaces!');
      expect(reportPath).toBeDefined();
      expect(reportPath.endsWith('.html')).toBe(true);
    });

    it('should handle empty scanPath', () => {
      const reportPath = getDefaultHtmlReportPath('');
      expect(reportPath).toBeDefined();
      expect(reportPath.startsWith('reports/')).toBe(true);
    });

    it('should produce unique paths for different calls', async () => {
      const path1 = getDefaultHtmlReportPath('/test/path');
      await new Promise(resolve => setTimeout(resolve, 10));
      const path2 = getDefaultHtmlReportPath('/test/path');
      expect(path1).not.toBe(path2);
    });
  });

  describe('saveHtmlReport', () => {
    it('should create the HTML report file', () => {
      const html = '<html><body>Test</body></html>';
      const filePath = path.join(tempDir, 'report.html');
      saveHtmlReport(html, filePath);
      expect(fs.existsSync(filePath)).toBe(true);
    });

    it('should save correct HTML content', () => {
      const html = '<html><body><h1>Test Report</h1></body></html>';
      const filePath = path.join(tempDir, 'report.html');
      saveHtmlReport(html, filePath);
      const content = fs.readFileSync(filePath, 'utf-8');
      expect(content).toBe(html);
    });

    it('should create nested directories if needed', () => {
      const html = '<html><body>Test</body></html>';
      const filePath = path.join(tempDir, 'nested', 'dir', 'report.html');
      saveHtmlReport(html, filePath);
      expect(fs.existsSync(filePath)).toBe(true);
    });

    it('should overwrite existing file', () => {
      const html1 = '<html><body>Report 1</body></html>';
      const html2 = '<html><body>Report 2</body></html>';
      const filePath = path.join(tempDir, 'report.html');

      saveHtmlReport(html1, filePath);
      saveHtmlReport(html2, filePath);

      const content = fs.readFileSync(filePath, 'utf-8');
      expect(content).toBe(html2);
    });

    it('should handle deeply nested non-existent directories', () => {
      const html = '<html><body>Test</body></html>';
      const filePath = path.join(tempDir, 'a', 'b', 'c', 'd', 'e', 'report.html');
      saveHtmlReport(html, filePath);
      expect(fs.existsSync(filePath)).toBe(true);
    });

    it('should handle unicode in HTML content', () => {
      const html = '<html><body>日本語 テスト 🚨</body></html>';
      const filePath = path.join(tempDir, 'unicode-report.html');
      saveHtmlReport(html, filePath);
      const content = fs.readFileSync(filePath, 'utf-8');
      expect(content).toContain('日本語');
    });

    it('should handle large HTML content', () => {
      const threats: Threat[] = [];
      for (let i = 0; i < 100; i++) {
        threats.push(createMockThreat({ file: `/test/file${i}.php`, type: 'php_eval', line: i }));
      }
      const data: HtmlReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ safe: false, threats }),
        suggestions: [],
      };
      const html = generateHtmlReport(data);
      const filePath = path.join(tempDir, 'large-report.html');
      saveHtmlReport(html, filePath);
      expect(fs.existsSync(filePath)).toBe(true);
      const content = fs.readFileSync(filePath, 'utf-8');
      expect(content.length).toBeGreaterThan(1000);
    });
  });

  describe('Severity classification', () => {
    it('should classify shell_exec as critical', () => {
      const threat = createMockThreat({ type: 'php_shell_exec' });
      const data: HtmlReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ safe: false, threats: [threat] }),
        suggestions: [],
      };
      const html = generateHtmlReport(data);
      expect(html).toContain('critical');
    });

    it('should classify eval as high', () => {
      const threat = createMockThreat({ type: 'php_eval' });
      const data: HtmlReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ safe: false, threats: [threat] }),
        suggestions: [],
      };
      const html = generateHtmlReport(data);
      expect(html).toContain('high');
    });

    it('should classify base64 patterns as medium', () => {
      const threat = createMockThreat({ type: 'base64_large' });
      const data: HtmlReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ safe: false, threats: [threat] }),
        suggestions: [],
      };
      const html = generateHtmlReport(data);
      expect(html).toContain('medium');
    });

    it('should classify get parameter as low', () => {
      const threat = createMockThreat({ type: 'php_get_parameter' });
      const data: HtmlReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ safe: false, threats: [threat] }),
        suggestions: [],
      };
      const html = generateHtmlReport(data);
      expect(html).toContain('low');
    });

    it('should classify unknown types as info', () => {
      const threat = createMockThreat({ type: 'unknown_pattern' });
      const data: HtmlReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ safe: false, threats: [threat] }),
        suggestions: [],
      };
      const html = generateHtmlReport(data);
      expect(html).toContain('info');
    });
  });

  describe('Full report generation and save', () => {
    it('should generate and save a complete report', () => {
      const threats: Threat[] = [
        createMockThreat({ file: '/test/backdoor.php', type: 'php_eval', line: 10, signature: 'eval(base64_decode(' }),
        createMockThreat({ file: '/test/shell.php', type: 'php_shell_exec', line: null, signature: 'shell_exec(' }),
      ];

      const vulnerabilities: Vulnerability[] = [
        { component: 'wordpress', version: '6.0', cve: 'CVE-2024-0001', title: 'XSS Vulnerability', severity: 'medium' },
      ];

      const integrity: IntegrityResult = {
        checked: 50,
        modified: 1,
        modifiedFiles: ['wp-login.php'],
        wordpressVersion: '6.0',
      };

      const data: HtmlReportData = {
        timestamp: '2024-01-15T10:30:00.000Z',
        scanPath: '/var/www/html',
        scanResult: createMockScanResult({ safe: false, threats, totalFiles: 50 }),
        vulnerabilities,
        integrity,
        suggestions: ['Remove backdoor.php', 'Update WordPress to latest version'],
      };

      const html = generateHtmlReport(data);
      const filePath = path.join(tempDir, 'full-report.html');
      saveHtmlReport(html, filePath);

      expect(fs.existsSync(filePath)).toBe(true);
      const content = fs.readFileSync(filePath, 'utf-8');

      expect(content).toContain('Clean Sweep Security Report');
      expect(content).toContain('/var/www/html');
      expect(content).toContain('THREATS DETECTED');
      expect(content).toContain('/test/backdoor.php');
      expect(content).toContain('/test/shell.php');
      expect(content).toContain('Known Vulnerabilities');
      expect(content).toContain('CVE-2024-0001');
      expect(content).toContain('File Integrity Check');
      expect(content).toContain('wp-login.php');
      expect(content).toContain('Remove backdoor.php');
      expect(content).toContain('Update WordPress to latest version');
    });

    it('should generate valid HTML for safe scan', () => {
      const data: HtmlReportData = {
        timestamp: '2024-01-15T10:30:00.000Z',
        scanPath: '/clean/site',
        scanResult: createMockScanResult({ safe: true, threats: [], totalFiles: 25 }),
        suggestions: [],
      };

      const html = generateHtmlReport(data);
      const filePath = path.join(tempDir, 'safe-report.html');
      saveHtmlReport(html, filePath);

      expect(fs.existsSync(filePath)).toBe(true);
      const content = fs.readFileSync(filePath, 'utf-8');

      expect(content).toContain('SAFE');
      expect(content).toContain('No threats detected');
      expect(content).toContain('25');
    });
  });
});
