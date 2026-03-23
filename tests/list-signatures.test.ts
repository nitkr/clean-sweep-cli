import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  loadAllSignatures,
  filterSignatures,
  formatSignaturesTable,
  getSignatureFiles,
} from '../src/commands/list-signatures';

describe('List Signatures Module', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'list-sig-test-'));
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('getSignatureFiles', () => {
    it('should return json files from signatures directory', () => {
      fs.writeFileSync(path.join(tempDir, 'sigs.json'), '{}');
      fs.writeFileSync(path.join(tempDir, 'other.json'), '{}');
      fs.writeFileSync(path.join(tempDir, 'readme.txt'), 'not json');

      const files = getSignatureFiles(tempDir);

      expect(files).toEqual(['other.json', 'sigs.json']);
    });

    it('should return empty array for non-existent directory', () => {
      const files = getSignatureFiles(path.join(tempDir, 'nonexistent'));

      expect(files).toEqual([]);
    });

    it('should return empty array for empty directory', () => {
      const files = getSignatureFiles(tempDir);

      expect(files).toEqual([]);
    });
  });

  describe('loadAllSignatures', () => {
    it('should load signatures from array-format files', () => {
      const sigFile = {
        version: '1.0.0',
        signatures: [
          { id: 'sig-001', name: 'Test Sig', severity: 'high', category: 'test', pattern: 'foo', type: 'bar' },
          { id: 'sig-002', name: 'Another Sig', severity: 'low', category: 'other', pattern: 'baz', type: 'qux' },
        ],
      };
      fs.writeFileSync(path.join(tempDir, 'test-sigs.json'), JSON.stringify(sigFile));

      const signatures = loadAllSignatures(tempDir);

      expect(signatures).toHaveLength(2);
      expect(signatures[0]).toEqual({ id: 'sig-001', name: 'Test Sig', severity: 'high', category: 'test' });
      expect(signatures[1]).toEqual({ id: 'sig-002', name: 'Another Sig', severity: 'low', category: 'other' });
    });

    it('should load signatures from object-format files (nested categories)', () => {
      const sigFile = {
        version: '1.0.0',
        signatures: {
          doubleExtensions: [
            { id: 'ext-001', name: 'Double Ext', severity: 'critical', pattern: '\\.php\\.jpg', type: 'double-ext' },
          ],
          maliciousFilenames: [
            { id: 'mal-001', name: 'Bad Name', severity: 'high', pattern: 'shell\\.php', type: 'malicious' },
          ],
        },
      };
      fs.writeFileSync(path.join(tempDir, 'file-patterns.json'), JSON.stringify(sigFile));

      const signatures = loadAllSignatures(tempDir);

      expect(signatures).toHaveLength(2);
      expect(signatures[0]).toEqual({ id: 'ext-001', name: 'Double Ext', severity: 'critical', category: 'doubleExtensions' });
      expect(signatures[1]).toEqual({ id: 'mal-001', name: 'Bad Name', severity: 'high', category: 'maliciousFilenames' });
    });

    it('should load from multiple files', () => {
      const phpSigs = {
        signatures: [
          { id: 'php-001', name: 'PHP Sig', severity: 'critical', category: 'rce', pattern: 'eval', type: 'webshell' },
        ],
      };
      const jsSigs = {
        signatures: [
          { id: 'js-001', name: 'JS Sig', severity: 'high', category: 'xss', pattern: 'eval', type: 'malicious' },
        ],
      };
      fs.writeFileSync(path.join(tempDir, 'php.json'), JSON.stringify(phpSigs));
      fs.writeFileSync(path.join(tempDir, 'js.json'), JSON.stringify(jsSigs));

      const signatures = loadAllSignatures(tempDir);

      expect(signatures).toHaveLength(2);
      expect(signatures.map(s => s.id).sort()).toEqual(['js-001', 'php-001']);
    });

    it('should default category to uncategorized when missing', () => {
      const sigFile = {
        signatures: [
          { id: 'sig-001', name: 'No Category', severity: 'medium', pattern: 'foo', type: 'bar' },
        ],
      };
      fs.writeFileSync(path.join(tempDir, 'no-cat.json'), JSON.stringify(sigFile));

      const signatures = loadAllSignatures(tempDir);

      expect(signatures[0].category).toBe('uncategorized');
    });

    it('should skip malformed JSON files', () => {
      fs.writeFileSync(path.join(tempDir, 'bad.json'), '{invalid json');
      const goodFile = {
        signatures: [
          { id: 'sig-001', name: 'Good', severity: 'low', category: 'ok', pattern: 'x', type: 'y' },
        ],
      };
      fs.writeFileSync(path.join(tempDir, 'good.json'), JSON.stringify(goodFile));

      const signatures = loadAllSignatures(tempDir);

      expect(signatures).toHaveLength(1);
      expect(signatures[0].id).toBe('sig-001');
    });

    it('should return empty array for empty directory', () => {
      const signatures = loadAllSignatures(tempDir);

      expect(signatures).toEqual([]);
    });

    it('should return empty array for non-existent directory', () => {
      const signatures = loadAllSignatures(path.join(tempDir, 'nope'));

      expect(signatures).toEqual([]);
    });

    it('should load actual project signature files', () => {
      const realSigsDir = path.resolve(__dirname, '..', 'signatures');
      const signatures = loadAllSignatures(realSigsDir);

      expect(signatures.length).toBeGreaterThan(0);

      // Verify each signature has required fields
      for (const sig of signatures) {
        expect(sig.id).toBeDefined();
        expect(sig.name).toBeDefined();
        expect(sig.severity).toBeDefined();
        expect(sig.category).toBeDefined();
      }
    });
  });

  describe('filterSignatures', () => {
    const sampleSignatures = [
      { id: 'sig-001', name: 'Sig 1', severity: 'critical', category: 'injection' },
      { id: 'sig-002', name: 'Sig 2', severity: 'high', category: 'xss' },
      { id: 'sig-003', name: 'Sig 3', severity: 'critical', category: 'xss' },
      { id: 'sig-004', name: 'Sig 4', severity: 'low', category: 'injection' },
      { id: 'sig-005', name: 'Sig 5', severity: 'medium', category: 'obfuscation' },
    ];

    it('should return all signatures with no filters', () => {
      const result = filterSignatures(sampleSignatures, {});

      expect(result).toHaveLength(5);
    });

    it('should filter by category', () => {
      const result = filterSignatures(sampleSignatures, { category: 'xss' });

      expect(result).toHaveLength(2);
      expect(result.map(s => s.id)).toEqual(['sig-002', 'sig-003']);
    });

    it('should filter by severity', () => {
      const result = filterSignatures(sampleSignatures, { severity: 'critical' });

      expect(result).toHaveLength(2);
      expect(result.map(s => s.id)).toEqual(['sig-001', 'sig-003']);
    });

    it('should filter by both category and severity', () => {
      const result = filterSignatures(sampleSignatures, { category: 'xss', severity: 'critical' });

      expect(result).toHaveLength(1);
      expect(result[0].id).toBe('sig-003');
    });

    it('should be case-insensitive for category filter', () => {
      const result = filterSignatures(sampleSignatures, { category: 'XSS' });

      expect(result).toHaveLength(2);
    });

    it('should be case-insensitive for severity filter', () => {
      const result = filterSignatures(sampleSignatures, { severity: 'CRITICAL' });

      expect(result).toHaveLength(2);
    });

    it('should return empty array when no matches', () => {
      const result = filterSignatures(sampleSignatures, { category: 'nonexistent' });

      expect(result).toEqual([]);
    });
  });

  describe('formatSignaturesTable', () => {
    it('should format signatures into a table', () => {
      const signatures = [
        { id: 'sig-001', name: 'Test Sig', severity: 'high', category: 'injection' },
      ];

      const output = formatSignaturesTable(signatures);

      expect(output).toContain('sig-001');
      expect(output).toContain('Test Sig');
      expect(output).toContain('high');
      expect(output).toContain('injection');
      expect(output).toContain('Total: 1 signature(s)');
    });

    it('should show header row', () => {
      const signatures = [
        { id: 'sig-001', name: 'Test', severity: 'low', category: 'test' },
      ];

      const output = formatSignaturesTable(signatures);

      expect(output).toContain('ID');
      expect(output).toContain('NAME');
      expect(output).toContain('SEVERITY');
      expect(output).toContain('CATEGORY');
    });

    it('should show separator line', () => {
      const signatures = [
        { id: 'sig-001', name: 'Test', severity: 'low', category: 'test' },
      ];

      const output = formatSignaturesTable(signatures);

      expect(output).toContain('-'.repeat(96));
    });

    it('should show correct total count', () => {
      const signatures = [
        { id: 'sig-001', name: 'Sig 1', severity: 'high', category: 'a' },
        { id: 'sig-002', name: 'Sig 2', severity: 'low', category: 'b' },
        { id: 'sig-003', name: 'Sig 3', severity: 'medium', category: 'c' },
      ];

      const output = formatSignaturesTable(signatures);

      expect(output).toContain('Total: 3 signature(s)');
    });

    it('should handle empty signatures array', () => {
      const output = formatSignaturesTable([]);

      expect(output).toBe('No signatures found.');
    });
  });
});
