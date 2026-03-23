import * as fs from 'fs';
import * as path from 'path';
import { describe, it, expect } from '@jest/globals';

const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low'];

interface Signature {
  id: string;
  name: string;
  pattern: string;
  severity: string;
  [key: string]: unknown;
}

interface SignatureFile {
  version?: string;
  description?: string;
  lastUpdated?: string;
  signatures: Signature[] | { [key: string]: Signature[] };
}

function validateSignature(signature: Signature, fileName: string): string[] {
  const errors: string[] = [];

  if (!signature.id || typeof signature.id !== 'string') {
    errors.push(`${fileName}: Signature missing required field 'id'`);
  }
  if (!signature.name || typeof signature.name !== 'string') {
    errors.push(`${fileName}: Signature missing required field 'name'`);
  }
  if (!signature.pattern || typeof signature.pattern !== 'string') {
    errors.push(`${fileName}: Signature missing required field 'pattern'`);
  }
  if (!signature.severity || typeof signature.severity !== 'string') {
    errors.push(`${fileName}: Signature missing required field 'severity'`);
  } else if (!VALID_SEVERITIES.includes(signature.severity)) {
    errors.push(
      `${fileName}: Invalid severity '${signature.severity}'. Must be one of: ${VALID_SEVERITIES.join(', ')}`
    );
  }

  return errors;
}

function validateSignatureFile(filePath: string): string[] {
  const errors: string[] = [];
  const fileName = path.basename(filePath);

  const content = fs.readFileSync(filePath, 'utf-8');
  let data: SignatureFile;

  try {
    data = JSON.parse(content);
  } catch {
    errors.push(`${fileName}: Invalid JSON`);
    return errors;
  }

  if (!data.signatures) {
    errors.push(`${fileName}: Missing 'signatures' field`);
    return errors;
  }

  if (Array.isArray(data.signatures)) {
    data.signatures.forEach((sig, index) => {
      errors.push(...validateSignature(sig, `${fileName}[${index}]`));
    });
  } else {
    Object.entries(data.signatures).forEach(([category, signatures]) => {
      signatures.forEach((sig, index) => {
        errors.push(...validateSignature(sig, `${fileName}.${category}[${index}]`));
      });
    });
  }

  return errors;
}

describe('Signature Files', () => {
  const signaturesDir = path.join(__dirname, '..', 'signatures');

  it('should load and validate signatures/php-signatures.json', () => {
    const filePath = path.join(signaturesDir, 'php-signatures.json');
    const errors = validateSignatureFile(filePath);
    expect(errors).toHaveLength(0);
  });

  it('should load and validate signatures/js-signatures.json', () => {
    const filePath = path.join(signaturesDir, 'js-signatures.json');
    const errors = validateSignatureFile(filePath);
    expect(errors).toHaveLength(0);
  });

  it('should load and validate signatures/file-patterns.json', () => {
    const filePath = path.join(signaturesDir, 'file-patterns.json');
    const errors = validateSignatureFile(filePath);
    expect(errors).toHaveLength(0);
  });

  it('should have all required fields in every signature', () => {
    const files = ['php-signatures.json', 'js-signatures.json', 'file-patterns.json'];
    const requiredFields = ['id', 'name', 'pattern', 'severity'];

    files.forEach((file) => {
      const filePath = path.join(signaturesDir, file);
      const content = fs.readFileSync(filePath, 'utf-8');
      const data = JSON.parse(content) as SignatureFile;

      const signatures = Array.isArray(data.signatures)
        ? data.signatures
        : Object.values(data.signatures).flat();

      signatures.forEach((sig) => {
        requiredFields.forEach((field) => {
          expect(sig).toHaveProperty(field);
        });
      });
    });
  });

  it('should have valid severity levels in all signatures', () => {
    const files = ['php-signatures.json', 'js-signatures.json', 'file-patterns.json'];

    files.forEach((file) => {
      const filePath = path.join(signaturesDir, file);
      const content = fs.readFileSync(filePath, 'utf-8');
      const data = JSON.parse(content) as SignatureFile;

      const signatures = Array.isArray(data.signatures)
        ? data.signatures
        : Object.values(data.signatures).flat();

      signatures.forEach((sig) => {
        expect(VALID_SEVERITIES).toContain(sig.severity);
      });
    });
  });
});
