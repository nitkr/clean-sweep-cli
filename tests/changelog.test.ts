import { describe, it, expect } from '@jest/globals';
import {
  compareScanResults,
  generateChangelog,
  generateChangelogFromScan,
  ChangelogEntry,
  ChangelogOptions,
} from '../src/changelog';
import { ScanResult, Threat } from '../src/malware-scanner';

function makeScanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    path: '/test/site',
    files: ['/test/site/index.php', '/test/site/style.css'],
    directories: ['/test/site/wp-content'],
    totalFiles: 2,
    totalDirectories: 1,
    threats: [],
    safe: true,
    dryRun: false,
    whitelisted: 0,
    ...overrides,
  };
}

function makeThreat(overrides: Partial<Threat> = {}): Threat {
  return {
    file: '/test/site/malicious.php',
    type: 'php_eval',
    line: null,
    signature: 'eval(',
    ...overrides,
  };
}

describe('Changelog', () => {
  describe('compareScanResults', () => {
    it('should report no changes when scans are identical', () => {
      const prev = makeScanResult();
      const curr = makeScanResult();
      const entry = compareScanResults(prev, curr);

      expect(entry.summary).toBe('No changes detected');
      expect(entry.threatsAdded).toHaveLength(0);
      expect(entry.threatsRemoved).toHaveLength(0);
      expect(entry.filesAdded).toHaveLength(0);
      expect(entry.filesRemoved).toHaveLength(0);
      expect(entry.statusChanged).toBe(false);
      expect(entry.previousStatus).toBe('SAFE');
      expect(entry.currentStatus).toBe('SAFE');
    });

    it('should detect new threats', () => {
      const prev = makeScanResult();
      const threat = makeThreat();
      const curr = makeScanResult({
        threats: [threat],
        safe: false,
      });

      const entry = compareScanResults(prev, curr);

      expect(entry.threatsAdded).toHaveLength(1);
      expect(entry.threatsAdded[0]).toEqual(threat);
      expect(entry.threatsRemoved).toHaveLength(0);
      expect(entry.statusChanged).toBe(true);
      expect(entry.previousStatus).toBe('SAFE');
      expect(entry.currentStatus).toBe('UNSAFE');
      expect(entry.summary).toContain('1 new threat(s) detected');
    });

    it('should detect resolved threats', () => {
      const threat = makeThreat();
      const prev = makeScanResult({
        threats: [threat],
        safe: false,
      });
      const curr = makeScanResult();

      const entry = compareScanResults(prev, curr);

      expect(entry.threatsAdded).toHaveLength(0);
      expect(entry.threatsRemoved).toHaveLength(1);
      expect(entry.threatsRemoved[0]).toEqual(threat);
      expect(entry.statusChanged).toBe(true);
      expect(entry.previousStatus).toBe('UNSAFE');
      expect(entry.currentStatus).toBe('SAFE');
      expect(entry.summary).toContain('1 threat(s) resolved');
    });

    it('should detect both added and removed threats', () => {
      const oldThreat = makeThreat({ file: '/test/old.php' });
      const newThreat = makeThreat({ file: '/test/new.php', type: 'php_shell_exec' });

      const prev = makeScanResult({ threats: [oldThreat], safe: false });
      const curr = makeScanResult({ threats: [newThreat], safe: false });

      const entry = compareScanResults(prev, curr);

      expect(entry.threatsAdded).toHaveLength(1);
      expect(entry.threatsAdded[0].file).toBe('/test/new.php');
      expect(entry.threatsRemoved).toHaveLength(1);
      expect(entry.threatsRemoved[0].file).toBe('/test/old.php');
      expect(entry.statusChanged).toBe(false);
      expect(entry.previousStatus).toBe('UNSAFE');
      expect(entry.currentStatus).toBe('UNSAFE');
    });

    it('should detect added files', () => {
      const prev = makeScanResult({
        files: ['/test/a.php'],
        totalFiles: 1,
      });
      const curr = makeScanResult({
        files: ['/test/a.php', '/test/b.php'],
        totalFiles: 2,
      });

      const entry = compareScanResults(prev, curr);

      expect(entry.filesAdded).toEqual(['/test/b.php']);
      expect(entry.filesRemoved).toHaveLength(0);
      expect(entry.summary).toContain('1 file(s) added');
    });

    it('should detect removed files', () => {
      const prev = makeScanResult({
        files: ['/test/a.php', '/test/b.php'],
        totalFiles: 2,
      });
      const curr = makeScanResult({
        files: ['/test/a.php'],
        totalFiles: 1,
      });

      const entry = compareScanResults(prev, curr);

      expect(entry.filesAdded).toHaveLength(0);
      expect(entry.filesRemoved).toEqual(['/test/b.php']);
      expect(entry.summary).toContain('1 file(s) removed');
    });

    it('should include timestamp in ISO format', () => {
      const prev = makeScanResult();
      const curr = makeScanResult();
      const entry = compareScanResults(prev, curr);

      expect(entry.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
    });

    it('should handle multiple threats of different types', () => {
      const threats: Threat[] = [
        makeThreat({ file: '/a.php', type: 'php_eval' }),
        makeThreat({ file: '/b.php', type: 'php_shell_exec' }),
        makeThreat({ file: '/c.js', type: 'js_eval_dynamic' }),
      ];
      const prev = makeScanResult();
      const curr = makeScanResult({ threats, safe: false });

      const entry = compareScanResults(prev, curr);

      expect(entry.threatsAdded).toHaveLength(3);
      expect(entry.summary).toContain('3 new threat(s) detected');
    });

    it('should distinguish threats by file, type, and signature', () => {
      const t1 = makeThreat({ file: '/a.php', type: 'php_eval', signature: 'eval(' });
      const t2 = makeThreat({ file: '/a.php', type: 'php_eval', signature: 'different' });

      const prev = makeScanResult({ threats: [t1], safe: false });
      const curr = makeScanResult({ threats: [t2], safe: false });

      const entry = compareScanResults(prev, curr);

      expect(entry.threatsAdded).toHaveLength(1);
      expect(entry.threatsRemoved).toHaveLength(1);
    });
  });

  describe('generateChangelog', () => {
    it('should produce valid markdown output', () => {
      const entry: ChangelogEntry = {
        timestamp: '2025-01-01T00:00:00.000Z',
        summary: 'No changes detected',
        threatsAdded: [],
        threatsRemoved: [],
        filesAdded: [],
        filesRemoved: [],
        statusChanged: false,
        previousStatus: 'SAFE',
        currentStatus: 'SAFE',
      };

      const md = generateChangelog(entry);

      expect(md).toContain('# Clean Sweep Changelog');
      expect(md).toContain('## Summary');
      expect(md).toContain('## Status');
      expect(md).toContain('No changes detected');
    });

    it('should respect custom title', () => {
      const entry: ChangelogEntry = {
        timestamp: '2025-01-01T00:00:00.000Z',
        summary: 'test',
        threatsAdded: [],
        threatsRemoved: [],
        filesAdded: [],
        filesRemoved: [],
        statusChanged: false,
        previousStatus: 'SAFE',
        currentStatus: 'SAFE',
      };

      const md = generateChangelog(entry, { title: 'My Report' });

      expect(md).toContain('# My Report');
    });

    it('should omit timestamp when includeTimestamp is false', () => {
      const entry: ChangelogEntry = {
        timestamp: '2025-01-01T00:00:00.000Z',
        summary: 'test',
        threatsAdded: [],
        threatsRemoved: [],
        filesAdded: [],
        filesRemoved: [],
        statusChanged: false,
        previousStatus: 'SAFE',
        currentStatus: 'SAFE',
      };

      const md = generateChangelog(entry, { includeTimestamp: false });

      expect(md).not.toContain('Generated:');
    });

    it('should include new threats section', () => {
      const entry: ChangelogEntry = {
        timestamp: '2025-01-01T00:00:00.000Z',
        summary: '1 new threat(s) detected',
        threatsAdded: [makeThreat()],
        threatsRemoved: [],
        filesAdded: [],
        filesRemoved: [],
        statusChanged: true,
        previousStatus: 'SAFE',
        currentStatus: 'UNSAFE',
      };

      const md = generateChangelog(entry);

      expect(md).toContain('## New Threats');
      expect(md).toContain('php_eval');
      expect(md).toContain('/test/site/malicious.php');
    });

    it('should include resolved threats section', () => {
      const entry: ChangelogEntry = {
        timestamp: '2025-01-01T00:00:00.000Z',
        summary: '1 threat(s) resolved',
        threatsAdded: [],
        threatsRemoved: [makeThreat()],
        filesAdded: [],
        filesRemoved: [],
        statusChanged: true,
        previousStatus: 'UNSAFE',
        currentStatus: 'SAFE',
      };

      const md = generateChangelog(entry);

      expect(md).toContain('## Resolved Threats');
      expect(md).toContain('php_eval');
    });

    it('should include line numbers when present', () => {
      const entry: ChangelogEntry = {
        timestamp: '2025-01-01T00:00:00.000Z',
        summary: 'test',
        threatsAdded: [makeThreat({ line: 42 })],
        threatsRemoved: [],
        filesAdded: [],
        filesRemoved: [],
        statusChanged: false,
        previousStatus: 'SAFE',
        currentStatus: 'SAFE',
      };

      const md = generateChangelog(entry);

      expect(md).toContain(':42');
    });

    it('should include file sections when includeFileInfo is true', () => {
      const entry: ChangelogEntry = {
        timestamp: '2025-01-01T00:00:00.000Z',
        summary: 'test',
        threatsAdded: [],
        threatsRemoved: [],
        filesAdded: ['/test/new.php'],
        filesRemoved: ['/test/old.php'],
        statusChanged: false,
        previousStatus: 'SAFE',
        currentStatus: 'SAFE',
      };

      const md = generateChangelog(entry, { includeFileInfo: true });

      expect(md).toContain('## Files Added');
      expect(md).toContain('## Files Removed');
      expect(md).toContain('/test/new.php');
      expect(md).toContain('/test/old.php');
    });

    it('should omit file sections when includeFileInfo is false', () => {
      const entry: ChangelogEntry = {
        timestamp: '2025-01-01T00:00:00.000Z',
        summary: 'test',
        threatsAdded: [],
        threatsRemoved: [],
        filesAdded: ['/test/new.php'],
        filesRemoved: ['/test/old.php'],
        statusChanged: false,
        previousStatus: 'SAFE',
        currentStatus: 'SAFE',
      };

      const md = generateChangelog(entry, { includeFileInfo: false });

      expect(md).not.toContain('## Files Added');
      expect(md).not.toContain('## Files Removed');
    });

    it('should group threats by type when groupByType is true', () => {
      const entry: ChangelogEntry = {
        timestamp: '2025-01-01T00:00:00.000Z',
        summary: 'test',
        threatsAdded: [
          makeThreat({ file: '/a.php', type: 'php_eval' }),
          makeThreat({ file: '/b.php', type: 'php_eval' }),
          makeThreat({ file: '/c.js', type: 'js_eval_dynamic' }),
        ],
        threatsRemoved: [],
        filesAdded: [],
        filesRemoved: [],
        statusChanged: false,
        previousStatus: 'SAFE',
        currentStatus: 'SAFE',
      };

      const md = generateChangelog(entry, { groupByType: true });

      expect(md).toContain('### php_eval');
      expect(md).toContain('### js_eval_dynamic');
    });

    it('should show status unchanged when no change', () => {
      const entry: ChangelogEntry = {
        timestamp: '2025-01-01T00:00:00.000Z',
        summary: 'test',
        threatsAdded: [],
        threatsRemoved: [],
        filesAdded: [],
        filesRemoved: [],
        statusChanged: false,
        previousStatus: 'SAFE',
        currentStatus: 'SAFE',
      };

      const md = generateChangelog(entry);

      expect(md).toContain('(unchanged)');
    });

    it('should show status transition when changed', () => {
      const entry: ChangelogEntry = {
        timestamp: '2025-01-01T00:00:00.000Z',
        summary: 'Status changed',
        threatsAdded: [makeThreat()],
        threatsRemoved: [],
        filesAdded: [],
        filesRemoved: [],
        statusChanged: true,
        previousStatus: 'SAFE',
        currentStatus: 'UNSAFE',
      };

      const md = generateChangelog(entry);

      expect(md).toContain('**Previous:** SAFE');
      expect(md).toContain('**Current:** UNSAFE');
      expect(md).not.toContain('(unchanged)');
    });
  });

  describe('generateChangelogFromScan', () => {
    it('should generate a report from a single scan result', () => {
      const scan = makeScanResult({
        threats: [makeThreat()],
        safe: false,
      });

      const md = generateChangelogFromScan(scan);

      expect(md).toContain('# Clean Sweep Scan Report');
      expect(md).toContain('## Overview');
      expect(md).toContain('/test/site');
      expect(md).toContain('UNSAFE');
      expect(md).toContain('## Threats');
      expect(md).toContain('### php_eval');
    });

    it('should show SAFE status for clean scan', () => {
      const scan = makeScanResult();

      const md = generateChangelogFromScan(scan);

      expect(md).toContain('SAFE');
      expect(md).not.toContain('## Threats');
      expect(md).not.toContain('## Recommendations');
    });

    it('should include recommendations for unsafe scan', () => {
      const scan = makeScanResult({
        threats: [makeThreat()],
        safe: false,
      });

      const md = generateChangelogFromScan(scan);

      expect(md).toContain('## Recommendations');
      expect(md).toContain('Review flagged files');
    });

    it('should show whitelisted count when present', () => {
      const scan = makeScanResult({ whitelisted: 3 });

      const md = generateChangelogFromScan(scan);

      expect(md).toContain('Whitelisted:** 3');
    });

    it('should not show whitelisted when zero', () => {
      const scan = makeScanResult({ whitelisted: 0 });

      const md = generateChangelogFromScan(scan);

      expect(md).not.toContain('Whitelisted');
    });

    it('should respect custom title', () => {
      const scan = makeScanResult();

      const md = generateChangelogFromScan(scan, { title: 'Weekly Scan' });

      expect(md).toContain('# Weekly Scan');
    });

    it('should omit timestamp when includeTimestamp is false', () => {
      const scan = makeScanResult();

      const md = generateChangelogFromScan(scan, { includeTimestamp: false });

      expect(md).not.toContain('Generated:');
    });

    it('should group threats by type', () => {
      const scan = makeScanResult({
        threats: [
          makeThreat({ file: '/a.php', type: 'php_eval' }),
          makeThreat({ file: '/b.php', type: 'php_eval' }),
          makeThreat({ file: '/c.js', type: 'js_eval_dynamic' }),
        ],
        safe: false,
      });

      const md = generateChangelogFromScan(scan);

      expect(md).toContain('### php_eval (2)');
      expect(md).toContain('### js_eval_dynamic (1)');
    });

    it('should include file and directory counts', () => {
      const scan = makeScanResult({
        totalFiles: 42,
        totalDirectories: 7,
      });

      const md = generateChangelogFromScan(scan);

      expect(md).toContain('Total Files:** 42');
      expect(md).toContain('Total Directories:** 7');
    });
  });

  describe('integration: compareScanResults + generateChangelog', () => {
    it('should produce a complete changelog from two scans', () => {
      const prev = makeScanResult({
        files: ['/a.php', '/b.php'],
        threats: [makeThreat({ file: '/a.php', type: 'php_eval' })],
        safe: false,
      });
      const curr = makeScanResult({
        files: ['/a.php', '/c.php'],
        threats: [makeThreat({ file: '/c.php', type: 'php_shell_exec' })],
        safe: false,
      });

      const entry = compareScanResults(prev, curr);
      const md = generateChangelog(entry);

      expect(md).toContain('## New Threats');
      expect(md).toContain('## Resolved Threats');
      expect(md).toContain('## Files Added');
      expect(md).toContain('## Files Removed');
      expect(md).toContain('/c.php');
      expect(md).toContain('/b.php');
    });
  });
});
