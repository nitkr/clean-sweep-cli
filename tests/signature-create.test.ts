import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  validateSignature,
  getCustomSignaturesPath,
  loadCustomSignatures,
  addSignatureToFile,
  formatCreateResult,
  SignatureInput,
  CustomSignaturesFile,
} from '../src/commands/signature-create';

describe('Signature Create Module', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sig-create-test-'));
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('validateSignature', () => {
    it('should return no errors for valid input', () => {
      const input: SignatureInput = {
        id: 'custom-001',
        name: 'Test Signature',
        pattern: 'eval\\s*\\(',
        severity: 'high',
      };

      const errors = validateSignature(input);

      expect(errors).toEqual([]);
    });

    it('should accept optional description and category', () => {
      const input: SignatureInput = {
        id: 'custom-001',
        name: 'Test',
        pattern: 'eval',
        severity: 'critical',
        description: 'A test signature',
        category: 'webshell',
      };

      const errors = validateSignature(input);

      expect(errors).toEqual([]);
    });

    it('should require id', () => {
      const input: SignatureInput = {
        id: '',
        name: 'Test',
        pattern: 'eval',
        severity: 'high',
      };

      const errors = validateSignature(input);

      expect(errors).toContain('Signature ID is required (--id)');
    });

    it('should require name', () => {
      const input: SignatureInput = {
        id: 'custom-001',
        name: '',
        pattern: 'eval',
        severity: 'high',
      };

      const errors = validateSignature(input);

      expect(errors).toContain('Signature name is required (--name)');
    });

    it('should require pattern', () => {
      const input: SignatureInput = {
        id: 'custom-001',
        name: 'Test',
        pattern: '',
        severity: 'high',
      };

      const errors = validateSignature(input);

      expect(errors).toContain('Signature pattern is required (--pattern)');
    });

    it('should require severity', () => {
      const input: SignatureInput = {
        id: 'custom-001',
        name: 'Test',
        pattern: 'eval',
        severity: '',
      };

      const errors = validateSignature(input);

      expect(errors).toContain('Severity is required (--severity)');
    });

    it('should reject invalid severity', () => {
      const input: SignatureInput = {
        id: 'custom-001',
        name: 'Test',
        pattern: 'eval',
        severity: 'extreme',
      };

      const errors = validateSignature(input);

      expect(errors).toContain('Invalid severity "extreme". Must be one of: critical, high, medium, low');
    });

    it('should accept all valid severities', () => {
      for (const sev of ['critical', 'high', 'medium', 'low']) {
        const input: SignatureInput = {
          id: 'custom-001',
          name: 'Test',
          pattern: 'eval',
          severity: sev,
        };

        const errors = validateSignature(input);

        expect(errors).toEqual([]);
      }
    });

    it('should reject invalid regex pattern', () => {
      const input: SignatureInput = {
        id: 'custom-001',
        name: 'Test',
        pattern: '[invalid(regex',
        severity: 'high',
      };

      const errors = validateSignature(input);

      expect(errors.some(e => e.startsWith('Invalid regex pattern'))).toBe(true);
    });

    it('should return multiple errors at once', () => {
      const input: SignatureInput = {
        id: '',
        name: '',
        pattern: '',
        severity: '',
      };

      const errors = validateSignature(input);

      expect(errors.length).toBeGreaterThanOrEqual(4);
    });
  });

  describe('getCustomSignaturesPath', () => {
    it('should use provided path', () => {
      const result = getCustomSignaturesPath('/tmp/my-sigs.json');

      expect(result).toBe('/tmp/my-sigs.json');
    });

    it('should default to custom-signatures.json in cwd', () => {
      const result = getCustomSignaturesPath();

      expect(result).toBe(path.resolve(process.cwd(), 'custom-signatures.json'));
    });
  });

  describe('loadCustomSignatures', () => {
    it('should return empty structure for non-existent file', () => {
      const result = loadCustomSignatures(path.join(tempDir, 'nonexistent.json'));

      expect(result.version).toBe('1.0.0');
      expect(result.signatures).toEqual([]);
    });

    it('should load existing custom signatures file', () => {
      const existing: CustomSignaturesFile = {
        version: '1.0.0',
        description: 'Custom malware signatures',
        signatures: [
          { id: 'custom-001', name: 'Existing', pattern: 'test', severity: 'low' },
        ],
      };
      const filePath = path.join(tempDir, 'custom-signatures.json');
      fs.writeFileSync(filePath, JSON.stringify(existing));

      const result = loadCustomSignatures(filePath);

      expect(result.signatures).toHaveLength(1);
      expect(result.signatures[0].id).toBe('custom-001');
    });

    it('should return empty structure for malformed JSON', () => {
      const filePath = path.join(tempDir, 'bad.json');
      fs.writeFileSync(filePath, '{invalid json');

      const result = loadCustomSignatures(filePath);

      expect(result.signatures).toEqual([]);
    });

    it('should return empty structure for JSON without signatures array', () => {
      const filePath = path.join(tempDir, 'no-sigs.json');
      fs.writeFileSync(filePath, JSON.stringify({ version: '1.0.0' }));

      const result = loadCustomSignatures(filePath);

      expect(result.signatures).toEqual([]);
    });
  });

  describe('addSignatureToFile', () => {
    it('should create a new signatures file', () => {
      const filePath = path.join(tempDir, 'custom-signatures.json');
      const input: SignatureInput = {
        id: 'custom-001',
        name: 'Test Sig',
        pattern: 'eval\\s*\\(',
        severity: 'high',
      };

      const result = addSignatureToFile(input, filePath);

      expect(result.created).toBe(true);
      expect(result.signature.id).toBe('custom-001');
      expect(fs.existsSync(filePath)).toBe(true);

      const saved = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      expect(saved.signatures).toHaveLength(1);
      expect(saved.signatures[0].id).toBe('custom-001');
    });

    it('should append to existing signatures file', () => {
      const filePath = path.join(tempDir, 'custom-signatures.json');
      const existing: CustomSignaturesFile = {
        version: '1.0.0',
        description: 'Custom malware signatures',
        signatures: [
          { id: 'existing-001', name: 'Old', pattern: 'old', severity: 'low' },
        ],
      };
      fs.writeFileSync(filePath, JSON.stringify(existing));

      const input: SignatureInput = {
        id: 'new-001',
        name: 'New Sig',
        pattern: 'new_pattern',
        severity: 'critical',
      };

      const result = addSignatureToFile(input, filePath);

      expect(result.created).toBe(true);

      const saved = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      expect(saved.signatures).toHaveLength(2);
      expect(saved.signatures[0].id).toBe('existing-001');
      expect(saved.signatures[1].id).toBe('new-001');
    });

    it('should reject duplicate signature IDs', () => {
      const filePath = path.join(tempDir, 'custom-signatures.json');
      const existing: CustomSignaturesFile = {
        version: '1.0.0',
        description: 'Custom malware signatures',
        signatures: [
          { id: 'dup-001', name: 'Existing', pattern: 'x', severity: 'low' },
        ],
      };
      fs.writeFileSync(filePath, JSON.stringify(existing));

      const input: SignatureInput = {
        id: 'dup-001',
        name: 'Duplicate',
        pattern: 'y',
        severity: 'high',
      };

      expect(() => addSignatureToFile(input, filePath)).toThrow(
        'Signature with ID "dup-001" already exists'
      );
    });

    it('should include optional fields when provided', () => {
      const filePath = path.join(tempDir, 'custom-signatures.json');
      const input: SignatureInput = {
        id: 'custom-001',
        name: 'Full Sig',
        pattern: 'eval',
        severity: 'high',
        description: 'A signature with all fields',
        category: 'webshell',
      };

      addSignatureToFile(input, filePath);

      const saved = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      expect(saved.signatures[0].description).toBe('A signature with all fields');
      expect(saved.signatures[0].category).toBe('webshell');
    });

    it('should not include optional fields when not provided', () => {
      const filePath = path.join(tempDir, 'custom-signatures.json');
      const input: SignatureInput = {
        id: 'custom-001',
        name: 'Minimal Sig',
        pattern: 'eval',
        severity: 'high',
      };

      addSignatureToFile(input, filePath);

      const saved = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      expect(saved.signatures[0].description).toBeUndefined();
      expect(saved.signatures[0].category).toBeUndefined();
    });

    it('should normalize severity to lowercase', () => {
      const filePath = path.join(tempDir, 'custom-signatures.json');
      const input: SignatureInput = {
        id: 'custom-001',
        name: 'Test',
        pattern: 'eval',
        severity: 'CRITICAL',
      };

      addSignatureToFile(input, filePath);

      const saved = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      expect(saved.signatures[0].severity).toBe('critical');
    });

    it('should trim whitespace from fields', () => {
      const filePath = path.join(tempDir, 'custom-signatures.json');
      const input: SignatureInput = {
        id: '  custom-001  ',
        name: '  Test Sig  ',
        pattern: '  eval\\s*  ',
        severity: '  high  ',
      };

      addSignatureToFile(input, filePath);

      const saved = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      expect(saved.signatures[0].id).toBe('custom-001');
      expect(saved.signatures[0].name).toBe('Test Sig');
      expect(saved.signatures[0].pattern).toBe('eval\\s*');
      expect(saved.signatures[0].severity).toBe('high');
    });

    it('should create directory if it does not exist', () => {
      const nestedDir = path.join(tempDir, 'nested', 'deep');
      const filePath = path.join(nestedDir, 'custom-signatures.json');
      const input: SignatureInput = {
        id: 'custom-001',
        name: 'Test',
        pattern: 'eval',
        severity: 'high',
      };

      addSignatureToFile(input, filePath);

      expect(fs.existsSync(filePath)).toBe(true);
    });
  });

  describe('formatCreateResult', () => {
    it('should format result with all fields', () => {
      const result = {
        signature: {
          id: 'custom-001',
          name: 'Test Sig',
          pattern: 'eval\\s*\\(',
          severity: 'high',
          description: 'Test description',
          category: 'webshell',
        },
        filePath: '/tmp/custom-signatures.json',
        created: true,
      };

      const output = formatCreateResult(result);

      expect(output).toContain('Signature created successfully');
      expect(output).toContain('custom-001');
      expect(output).toContain('Test Sig');
      expect(output).toContain('eval\\s*\\(');
      expect(output).toContain('high');
      expect(output).toContain('Test description');
      expect(output).toContain('webshell');
      expect(output).toContain('/tmp/custom-signatures.json');
    });

    it('should format result without optional fields', () => {
      const result = {
        signature: {
          id: 'custom-001',
          name: 'Test Sig',
          pattern: 'eval',
          severity: 'low',
        },
        filePath: '/tmp/custom-signatures.json',
        created: true,
      };

      const output = formatCreateResult(result);

      expect(output).toContain('Signature created successfully');
      expect(output).toContain('custom-001');
      expect(output).not.toContain('Description:');
      expect(output).not.toContain('Category:');
    });
  });
});
