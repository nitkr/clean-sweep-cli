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
  });
});
