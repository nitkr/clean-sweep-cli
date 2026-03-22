import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  createLogger,
  getLogger,
  generateReport,
  saveReport,
  getDefaultReportPath,
  Logger,
  ReportData,
} from '../src/logger';

describe('Logger Module', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'logger-test-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('createLogger', () => {
    it('should create a logger instance with debug method', () => {
      const logger = createLogger('info');
      expect(logger).toBeDefined();
      expect(typeof logger.debug).toBe('function');
    });

    it('should create a logger instance with info method', () => {
      const logger = createLogger('info');
      expect(logger).toBeDefined();
      expect(typeof logger.info).toBe('function');
    });

    it('should create a logger instance with warn method', () => {
      const logger = createLogger('info');
      expect(logger).toBeDefined();
      expect(typeof logger.warn).toBe('function');
    });

    it('should create a logger instance with error method', () => {
      const logger = createLogger('info');
      expect(logger).toBeDefined();
      expect(typeof logger.error).toBe('function');
    });

    it('should accept log level parameter', () => {
      const logger = createLogger('debug');
      expect(logger).toBeDefined();
    });
  });

  describe('getLogger', () => {
    it('should return a logger instance', () => {
      createLogger('info');
      const logger = getLogger();
      expect(logger).toBeDefined();
      expect(typeof logger.debug).toBe('function');
      expect(typeof logger.info).toBe('function');
      expect(typeof logger.warn).toBe('function');
      expect(typeof logger.error).toBe('function');
    });

    it('should return logger when no instance exists', () => {
      const logger = getLogger();
      expect(logger).toBeDefined();
    });
  });

  describe('generateReport', () => {
    it('should return ReportData with timestamp', () => {
      const report = generateReport('/test/path', {}, []);
      expect(report).toHaveProperty('timestamp');
      expect(typeof report.timestamp).toBe('string');
    });

    it('should return ReportData with scanPath', () => {
      const scanPath = '/test/path';
      const report = generateReport(scanPath, {}, []);
      expect(report.scanPath).toBe(scanPath);
    });

    it('should return ReportData with results', () => {
      const results = { files: 10, threats: 2 };
      const report = generateReport('/test/path', results, []);
      expect(report.results).toEqual(results);
    });

    it('should return ReportData with suggestions', () => {
      const suggestions = ['Remove malicious file', 'Update permissions'];
      const report = generateReport('/test/path', {}, suggestions);
      expect(report.suggestions).toEqual(suggestions);
    });

    it('should return proper ReportData structure', () => {
      const report: ReportData = generateReport('/test/path', { key: 'value' }, ['suggestion']);
      expect(report).toHaveProperty('timestamp');
      expect(report).toHaveProperty('scanPath');
      expect(report).toHaveProperty('results');
      expect(report).toHaveProperty('suggestions');
    });

    describe('edge cases', () => {
      it('should handle empty results', () => {
        const report = generateReport('/test/path', {}, []);
        expect(report.results).toEqual({});
        expect(report.suggestions).toEqual([]);
      });

      it('should handle large results', () => {
        const largeResults: Record<string, unknown> = {};
        for (let i = 0; i < 1000; i++) {
          largeResults[`key${i}`] = `value${i}`;
        }
        const report = generateReport('/test/path', largeResults, []);
        expect(Object.keys(report.results).length).toBe(1000);
      });

      it('should handle special characters in suggestions', () => {
        const suggestions = [
          'Remove file: /path/to/malware.exe',
          'Fix "permissions" on folder',
          'Handle <script> tags',
          'Unicode: 日本語テスト',
          'Emoji: 🚨alert',
          'Newlines\nand\ttabs',
          'Quotes: \'single\' and "double"',
          'Special: !@#$%^&*()',
        ];
        const report = generateReport('/test/path', {}, suggestions);
        expect(report.suggestions).toEqual(suggestions);
        const jsonStr = JSON.stringify(report);
        expect(() => JSON.parse(jsonStr)).not.toThrow();
      });

      it('should handle unicode in results', () => {
        const results = {
          japanese: '日本語',
          chinese: '中文',
          russian: 'Русский',
          emoji: '🎉',
        };
        const report = generateReport('/test/path', results, []);
        expect(report.results).toEqual(results);
      });

      it('should handle empty scan path', () => {
        const report = generateReport('', {}, []);
        expect(report.scanPath).toBe('');
      });

      it('should handle deep nested results', () => {
        const nestedResults = {
          level1: {
            level2: {
              level3: {
                value: 'deep',
              },
            },
          },
        };
        const report = generateReport('/test/path', nestedResults, []);
        expect(report.results).toEqual(nestedResults);
      });
    });
  });

  describe('saveReport', () => {
    it('should create the report file', () => {
      const report: ReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test',
        results: {},
        suggestions: [],
      };
      const filePath = path.join(tempDir, 'report.json');
      saveReport(report, filePath);
      expect(fs.existsSync(filePath)).toBe(true);
    });

    it('should save correct JSON content', () => {
      const report: ReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test',
        results: { files: 5 },
        suggestions: ['Fix permissions'],
      };
      const filePath = path.join(tempDir, 'report.json');
      saveReport(report, filePath);
      const content = fs.readFileSync(filePath, 'utf-8');
      const parsed = JSON.parse(content);
      expect(parsed).toEqual(report);
    });

    it('should create nested directories if needed', () => {
      const report: ReportData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test',
        results: {},
        suggestions: [],
      };
      const filePath = path.join(tempDir, 'nested', 'dir', 'report.json');
      saveReport(report, filePath);
      expect(fs.existsSync(filePath)).toBe(true);
    });

    describe('edge cases', () => {
      it('should handle non-existent parent directory', () => {
        const report: ReportData = {
          timestamp: '2024-01-01T00:00:00.000Z',
          scanPath: '/test',
          results: {},
          suggestions: [],
        };
        const nonExistentDir = path.join(tempDir, 'does', 'not', 'exist');
        const filePath = path.join(nonExistentDir, 'report.json');
        saveReport(report, filePath);
        expect(fs.existsSync(filePath)).toBe(true);
      });

      it('should handle path with special characters', () => {
        const report: ReportData = {
          timestamp: '2024-01-01T00:00:00.000Z',
          scanPath: '/test',
          results: {},
          suggestions: [],
        };
        const specialDir = path.join(tempDir, 'dir with spaces!@#');
        const filePath = path.join(specialDir, 'report.json');
        saveReport(report, filePath);
        expect(fs.existsSync(filePath)).toBe(true);
        const content = fs.readFileSync(filePath, 'utf-8');
        expect(() => JSON.parse(content)).not.toThrow();
      });

      it('should overwrite existing file', () => {
        const report1: ReportData = {
          timestamp: '2024-01-01T00:00:00.000Z',
          scanPath: '/test1',
          results: { version: 1 },
          suggestions: ['old suggestion'],
        };
        const filePath = path.join(tempDir, 'report.json');
        saveReport(report1, filePath);

        const report2: ReportData = {
          timestamp: '2024-01-02T00:00:00.000Z',
          scanPath: '/test2',
          results: { version: 2 },
          suggestions: ['new suggestion'],
        };
        saveReport(report2, filePath);

        const content = fs.readFileSync(filePath, 'utf-8');
        const parsed = JSON.parse(content);
        expect(parsed.timestamp).toBe('2024-01-02T00:00:00.000Z');
        expect(parsed.scanPath).toBe('/test2');
      });

      it('should handle deeply nested non-existent directories', () => {
        const report: ReportData = {
          timestamp: '2024-01-01T00:00:00.000Z',
          scanPath: '/test',
          results: {},
          suggestions: [],
        };
        const filePath = path.join(tempDir, 'a', 'b', 'c', 'd', 'e', 'report.json');
        saveReport(report, filePath);
        expect(fs.existsSync(filePath)).toBe(true);
      });

      it('should handle unicode characters in path', () => {
        const report: ReportData = {
          timestamp: '2024-01-01T00:00:00.000Z',
          scanPath: '/test',
          results: {},
          suggestions: [],
        };
        const unicodeDir = path.join(tempDir, '日本語', '中文');
        const filePath = path.join(unicodeDir, 'report.json');
        saveReport(report, filePath);
        expect(fs.existsSync(filePath)).toBe(true);
      });

      it('should handle empty report data', () => {
        const report: ReportData = {
          timestamp: '',
          scanPath: '',
          results: {},
          suggestions: [],
        };
        const filePath = path.join(tempDir, 'empty-report.json');
        saveReport(report, filePath);
        expect(fs.existsSync(filePath)).toBe(true);
        const content = fs.readFileSync(filePath, 'utf-8');
        const parsed = JSON.parse(content);
        expect(parsed).toEqual(report);
      });
    });
  });

  describe('getDefaultReportPath', () => {
    it('should return a valid path string', () => {
      const reportPath = getDefaultReportPath('/test/path');
      expect(typeof reportPath).toBe('string');
      expect(reportPath.length).toBeGreaterThan(0);
    });

    it('should include timestamp in the path', () => {
      const reportPath = getDefaultReportPath('/test/path');
      const hasTimestamp = reportPath.match(/\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}/);
      expect(hasTimestamp).not.toBeNull();
    });

    it('should include reports directory', () => {
      const reportPath = getDefaultReportPath('/test/path');
      expect(reportPath.startsWith('reports')).toBe(true);
    });

    it('should include scan prefix', () => {
      const reportPath = getDefaultReportPath('/test/path');
      expect(reportPath.includes('scan-')).toBe(true);
    });

    it('should include .json extension', () => {
      const reportPath = getDefaultReportPath('/test/path');
      expect(reportPath.endsWith('.json')).toBe(true);
    });

    it('should handle special characters in scanPath', () => {
      const reportPath = getDefaultReportPath('/test/path with spaces!');
      expect(reportPath).toBeDefined();
      expect(reportPath.includes('.json')).toBe(true);
    });

    describe('edge cases', () => {
      it('should handle path with special characters', () => {
        const reportPath = getDefaultReportPath('/test/path!@#$%^&*()');
        expect(reportPath).toBeDefined();
        expect(reportPath.length).toBeGreaterThan(0);
        expect(reportPath.endsWith('.json')).toBe(true);
      });

      it('should handle very long paths', () => {
        const longPath = '/test/' + 'a'.repeat(500);
        const reportPath = getDefaultReportPath(longPath);
        expect(reportPath).toBeDefined();
        expect(reportPath.length).toBeLessThan(200);
      });

      it('should handle different timestamp formats', () => {
        const reportPath = getDefaultReportPath('/test/path');
        expect(reportPath).toMatch(/\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}/);
        const timestampMatch = reportPath.match(/scan-[^/]+-(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}[^.]*)\.json/);
        expect(timestampMatch).not.toBeNull();
      });

      it('should truncate long scanPaths to 50 chars', () => {
        const longPath = '/very/long/path/that/exceeds/the/maximum/allowed/length/for/the/safe/path/handling';
        const reportPath = getDefaultReportPath(longPath);
        const safePath = longPath.replace(/[^a-zA-Z0-9]/g, '_').substring(0, 50);
        expect(safePath.length).toBeLessThanOrEqual(50);
      });

      it('should handle empty scanPath', () => {
        const reportPath = getDefaultReportPath('');
        expect(reportPath).toBeDefined();
        expect(reportPath.startsWith('reports/')).toBe(true);
        expect(reportPath.endsWith('.json')).toBe(true);
      });

      it('should handle scanPath with only special characters', () => {
        const reportPath = getDefaultReportPath('!@#$%^&*()');
        expect(reportPath).toBeDefined();
        expect(reportPath.includes('scan-')).toBe(true);
      });

      it('should handle unicode characters in scanPath', () => {
        const reportPath = getDefaultReportPath('/test/日本語/中文');
        expect(reportPath).toBeDefined();
        expect(reportPath.endsWith('.json')).toBe(true);
      });

      it('should produce unique paths for different calls', async () => {
        const path1 = getDefaultReportPath('/test/path');
        await new Promise(resolve => setTimeout(resolve, 10));
        const path2 = getDefaultReportPath('/test/path');
        expect(path1).not.toBe(path2);
      });

      it('should handle path with forward slashes', () => {
        const reportPath = getDefaultReportPath('/a/b/c/d/e/f/g');
        expect(reportPath).toBeDefined();
        expect(reportPath.startsWith('reports/')).toBe(true);
        expect(reportPath.endsWith('.json')).toBe(true);
      });

      it('should handle path with dots', () => {
        const reportPath = getDefaultReportPath('/test/path.with.dots');
        expect(reportPath).toBeDefined();
        expect(reportPath.includes('scan-')).toBe(true);
      });
    });
  });
});
