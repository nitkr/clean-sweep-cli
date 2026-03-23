import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  getSignaturesDir,
  getSignatureUrl,
  validateSignatureJson,
  updateSignatures,
} from '../src/commands/update-signatures';

describe('Update Signatures Module', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'update-sigs-test-'));
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('getSignaturesDir', () => {
    it('should return an absolute path ending with signatures', () => {
      const dir = getSignaturesDir();
      expect(path.isAbsolute(dir)).toBe(true);
      expect(dir).toMatch(/signatures$/);
    });
  });

  describe('getSignatureUrl', () => {
    it('should return provided URL when given', () => {
      const url = getSignatureUrl('https://custom.example.com/sigs');
      expect(url).toBe('https://custom.example.com/sigs');
    });

    it('should return default URL when no argument and no env var', () => {
      const origEnv = process.env.CLEAN_SWEEP_SIGNATURE_URL;
      delete process.env.CLEAN_SWEEP_SIGNATURE_URL;

      const url = getSignatureUrl();
      expect(url).toBe('https://signatures.clean-sweep-cli.example.com');

      if (origEnv) process.env.CLEAN_SWEEP_SIGNATURE_URL = origEnv;
    });

    it('should prefer explicit URL over env var', () => {
      const origEnv = process.env.CLEAN_SWEEP_SIGNATURE_URL;
      process.env.CLEAN_SWEEP_SIGNATURE_URL = 'https://env.example.com/sigs';

      const url = getSignatureUrl('https://explicit.example.com/sigs');
      expect(url).toBe('https://explicit.example.com/sigs');

      if (origEnv) {
        process.env.CLEAN_SWEEP_SIGNATURE_URL = origEnv;
      } else {
        delete process.env.CLEAN_SWEEP_SIGNATURE_URL;
      }
    });
  });

  describe('validateSignatureJson', () => {
    it('should return true for valid JSON object', () => {
      expect(validateSignatureJson('{"key": "value"}')).toBe(true);
    });

    it('should return true for empty JSON object', () => {
      expect(validateSignatureJson('{}')).toBe(true);
    });

    it('should return true for JSON array', () => {
      expect(validateSignatureJson('[1, 2, 3]')).toBe(true);
    });

    it('should return false for invalid JSON', () => {
      expect(validateSignatureJson('not json')).toBe(false);
    });

    it('should return false for empty string', () => {
      expect(validateSignatureJson('')).toBe(false);
    });

    it('should return false for JSON null', () => {
      expect(validateSignatureJson('null')).toBe(false);
    });

    it('should return false for bare JSON string', () => {
      expect(validateSignatureJson('"hello"')).toBe(false);
    });

    it('should return false for bare JSON number', () => {
      expect(validateSignatureJson('42')).toBe(false);
    });
  });

  describe('updateSignatures', () => {
    it('should report all files to update in dry-run mode', async () => {
      const result = await updateSignatures({
        dryRun: true,
        url: 'https://example.com/sigs',
        signaturesDir: tempDir,
      });

      expect(result.dryRun).toBe(true);
      expect(result.source).toBe('https://example.com/sigs');
      expect(result.updated.length).toBe(4);
      expect(result.errors.length).toBe(0);
    });

    it('should skip existing files that match in non-dry-run mode', async () => {
      const signaturesDir = path.join(tempDir, 'signatures');
      fs.mkdirSync(signaturesDir);

      const existingContent = '{"signatures": []}';
      fs.writeFileSync(path.join(signaturesDir, 'php-signatures.json'), existingContent);

      const mockFetch = jest.fn<(url: string) => Promise<string>>().mockResolvedValue(existingContent);

      const result = await updateSignatures({
        dryRun: false,
        url: 'https://example.com/sigs',
        signaturesDir,
      }, mockFetch);

      expect(result.skipped).toContain('php-signatures.json');
    });

    it('should create signatures directory if it does not exist', async () => {
      const signaturesDir = path.join(tempDir, 'new-sigs');

      const result = await updateSignatures({
        dryRun: true,
        url: 'https://example.com/sigs',
        signaturesDir,
      });

      expect(result.updated.length).toBe(4);
    });

    it('should return timestamp in ISO format', async () => {
      const result = await updateSignatures({
        dryRun: true,
        url: 'https://example.com/sigs',
        signaturesDir: tempDir,
      });

      const parsed = new Date(result.timestamp);
      expect(parsed.toISOString()).toBe(result.timestamp);
    });
  });
});
