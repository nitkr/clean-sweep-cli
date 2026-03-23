import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  findReportFiles,
  parseReport,
  filterByDateRange,
  buildHistory,
  HistoryEntry,
} from '../src/commands/history';

function createReportFile(dir: string, filename: string, data: object): string {
  const filePath = path.join(dir, filename);
  fs.writeFileSync(filePath, JSON.stringify(data));
  return filePath;
}

function makeReport(timestamp: string, threatCount: number, scanPath: string = '/test/path'): object {
  const threats = Array.from({ length: threatCount }, (_, i) => ({
    file: `file${i}.php`,
    type: 'php_eval',
    line: i + 1,
    signature: 'eval(',
  }));
  return {
    timestamp,
    scanPath,
    results: {
      threats,
      safe: threatCount === 0,
      path: scanPath,
      files: [],
      directories: [],
      totalFiles: 0,
      totalDirectories: 0,
      dryRun: false,
    },
    suggestions: [],
  };
}

describe('History Module', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'history-test-'));
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('findReportFiles', () => {
    it('should return empty array when reports directory does not exist', () => {
      const result = findReportFiles('/nonexistent/path');
      expect(result).toEqual([]);
    });

    it('should find all JSON files in reports directory', () => {
      createReportFile(tempDir, 'scan-001.json', makeReport('2026-01-01T00:00:00Z', 0));
      createReportFile(tempDir, 'scan-002.json', makeReport('2026-01-02T00:00:00Z', 1));
      fs.writeFileSync(path.join(tempDir, 'notes.txt'), 'not a report');

      const result = findReportFiles(tempDir);
      expect(result).toHaveLength(2);
      expect(result.every(f => f.endsWith('.json'))).toBe(true);
    });

    it('should return files sorted by name', () => {
      createReportFile(tempDir, 'scan-b.json', makeReport('2026-01-01T00:00:00Z', 0));
      createReportFile(tempDir, 'scan-a.json', makeReport('2026-01-02T00:00:00Z', 1));

      const result = findReportFiles(tempDir);
      expect(path.basename(result[0])).toBe('scan-a.json');
      expect(path.basename(result[1])).toBe('scan-b.json');
    });

    it('should return empty array when directory has no JSON files', () => {
      fs.writeFileSync(path.join(tempDir, 'notes.txt'), 'not json');
      const result = findReportFiles(tempDir);
      expect(result).toEqual([]);
    });
  });

  describe('parseReport', () => {
    it('should parse a valid report file', () => {
      const filePath = createReportFile(tempDir, 'valid.json', makeReport('2026-03-15T10:00:00Z', 3));

      const result = parseReport(filePath);
      expect(result).not.toBeNull();
      expect(result!.timestamp).toBe('2026-03-15T10:00:00Z');
      expect(result!.scanPath).toBe('/test/path');
      expect(result!.results.threats).toHaveLength(3);
      expect(result!.results.safe).toBe(false);
    });

    it('should return null for non-existent file', () => {
      const result = parseReport(path.join(tempDir, 'missing.json'));
      expect(result).toBeNull();
    });

    it('should return null for invalid JSON', () => {
      const filePath = path.join(tempDir, 'bad.json');
      fs.writeFileSync(filePath, 'not json');
      const result = parseReport(filePath);
      expect(result).toBeNull();
    });

    it('should return null when timestamp is missing', () => {
      const filePath = createReportFile(tempDir, 'no-ts.json', {
        scanPath: '/test',
        results: { threats: [], safe: true },
      });
      const result = parseReport(filePath);
      expect(result).toBeNull();
    });

    it('should return null when results is missing', () => {
      const filePath = createReportFile(tempDir, 'no-results.json', {
        timestamp: '2026-01-01T00:00:00Z',
        scanPath: '/test',
      });
      const result = parseReport(filePath);
      expect(result).toBeNull();
    });

    it('should return null when threats array is missing', () => {
      const filePath = createReportFile(tempDir, 'no-threats.json', {
        timestamp: '2026-01-01T00:00:00Z',
        scanPath: '/test',
        results: { safe: true },
      });
      const result = parseReport(filePath);
      expect(result).toBeNull();
    });

    it('should return null when safe boolean is missing', () => {
      const filePath = createReportFile(tempDir, 'no-safe.json', {
        timestamp: '2026-01-01T00:00:00Z',
        scanPath: '/test',
        results: { threats: [] },
      });
      const result = parseReport(filePath);
      expect(result).toBeNull();
    });
  });

  describe('filterByDateRange', () => {
    const entries: HistoryEntry[] = [
      { file: 'a.json', timestamp: '2026-01-01T00:00:00Z', scanPath: '/a', threatCount: 0, safe: true },
      { file: 'b.json', timestamp: '2026-02-15T00:00:00Z', scanPath: '/b', threatCount: 1, safe: false },
      { file: 'c.json', timestamp: '2026-03-10T00:00:00Z', scanPath: '/c', threatCount: 2, safe: false },
      { file: 'd.json', timestamp: '2026-04-20T00:00:00Z', scanPath: '/d', threatCount: 0, safe: true },
    ];

    it('should return all entries when no filters applied', () => {
      const result = filterByDateRange(entries);
      expect(result).toHaveLength(4);
    });

    it('should filter by from date', () => {
      const result = filterByDateRange(entries, '2026-02-01T00:00:00Z');
      expect(result).toHaveLength(3);
      expect(result[0].file).toBe('b.json');
    });

    it('should filter by to date', () => {
      const result = filterByDateRange(entries, undefined, '2026-03-01T00:00:00Z');
      expect(result).toHaveLength(2);
      expect(result[1].file).toBe('b.json');
    });

    it('should filter by both from and to dates', () => {
      const result = filterByDateRange(entries, '2026-02-01T00:00:00Z', '2026-03-15T00:00:00Z');
      expect(result).toHaveLength(2);
      expect(result[0].file).toBe('b.json');
      expect(result[1].file).toBe('c.json');
    });

    it('should include entries on boundary dates', () => {
      const result = filterByDateRange(entries, '2026-02-15T00:00:00Z', '2026-02-15T00:00:00Z');
      expect(result).toHaveLength(1);
      expect(result[0].file).toBe('b.json');
    });

    it('should throw for invalid from date', () => {
      expect(() => filterByDateRange(entries, 'not-a-date')).toThrow("Invalid 'from' date");
    });

    it('should throw for invalid to date', () => {
      expect(() => filterByDateRange(entries, undefined, 'invalid')).toThrow("Invalid 'to' date");
    });

    it('should return empty when no entries match', () => {
      const result = filterByDateRange(entries, '2026-06-01T00:00:00Z');
      expect(result).toHaveLength(0);
    });
  });

  describe('buildHistory', () => {
    it('should build history from report files', () => {
      createReportFile(tempDir, 'scan-001.json', makeReport('2026-01-15T10:00:00Z', 0, '/site1'));
      createReportFile(tempDir, 'scan-002.json', makeReport('2026-02-20T14:30:00Z', 5, '/site2'));
      createReportFile(tempDir, 'scan-003.json', makeReport('2026-03-10T09:00:00Z', 2, '/site1'));

      const result = buildHistory(tempDir);

      expect(result.total).toBe(3);
      expect(result.scans).toHaveLength(3);

      expect(result.scans[0].file).toBe('scan-001.json');
      expect(result.scans[0].timestamp).toBe('2026-01-15T10:00:00Z');
      expect(result.scans[0].threatCount).toBe(0);
      expect(result.scans[0].safe).toBe(true);

      expect(result.scans[1].threatCount).toBe(5);
      expect(result.scans[1].safe).toBe(false);

      expect(result.scans[2].threatCount).toBe(2);
      expect(result.scans[2].safe).toBe(false);
    });

    it('should return empty result when reports directory does not exist', () => {
      const result = buildHistory('/nonexistent/dir');
      expect(result.total).toBe(0);
      expect(result.scans).toEqual([]);
    });

    it('should skip invalid report files', () => {
      createReportFile(tempDir, 'valid.json', makeReport('2026-01-15T10:00:00Z', 3));
      fs.writeFileSync(path.join(tempDir, 'invalid.json'), 'not valid json');
      createReportFile(tempDir, 'also-valid.json', makeReport('2026-02-15T10:00:00Z', 1));

      const result = buildHistory(tempDir);

      expect(result.total).toBe(2);
      expect(result.scans.map(s => s.file)).toEqual(['also-valid.json', 'valid.json']);
    });

    it('should filter by date range', () => {
      createReportFile(tempDir, 'early.json', makeReport('2026-01-15T10:00:00Z', 1));
      createReportFile(tempDir, 'mid.json', makeReport('2026-02-15T10:00:00Z', 2));
      createReportFile(tempDir, 'late.json', makeReport('2026-03-15T10:00:00Z', 3));

      const result = buildHistory(tempDir, '2026-02-01T00:00:00Z', '2026-02-28T00:00:00Z');

      expect(result.total).toBe(1);
      expect(result.scans[0].file).toBe('mid.json');
    });

    it('should count threats correctly for zero-threat reports', () => {
      createReportFile(tempDir, 'clean.json', makeReport('2026-01-15T10:00:00Z', 0));

      const result = buildHistory(tempDir);

      expect(result.total).toBe(1);
      expect(result.scans[0].threatCount).toBe(0);
      expect(result.scans[0].safe).toBe(true);
    });
  });
});
