/**
 * Generate Obfuscated Signatures Utility
 * 
 * This script reads the source signature files and generates obfuscated versions
 * that can be stored in the production signatures/ directory.
 * 
 * IMPORTANT: The unobfuscated signatures should NEVER be pushed to remote repositories.
 * This script generates an unobfuscated reference file that should be added to .gitignore.
 * 
 * Usage:
 *   npx ts-node src/generate-obfuscated-signatures.ts
 * 
 * Output:
 *   - signatures/php-signatures.json (obfuscated - safe to commit)
 *   - src/reference-signatures.ts (unobfuscated reference - DO NOT COMMIT)
 */

import * as fs from 'fs';
import * as path from 'path';
import { obfuscateSignatures, generateKey } from './signature-obfuscator';

// Secret key for obfuscation - in production, this should be provided via environment variable
// or secure secret management. For now, we generate a random key each time.
const OBFUSCATION_KEY = process.env.SIGNATURE_OBFUSCATION_KEY || generateKey(24);

interface Signature {
  id: string;
  name?: string;
  description?: string;
  severity: string;
  pattern: string;
  type?: string;
  category?: string;
}

interface SignatureFile {
  version?: string;
  description?: string;
  lastUpdated?: string;
  signatures: Signature[];
}

function loadSignatureFile(filePath: string): SignatureFile {
  const content = fs.readFileSync(filePath, 'utf-8');
  return JSON.parse(content);
}

function saveSignatureFile(filePath: string, data: SignatureFile): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');
}

function generateReferenceFile(filePath: string, signatures: any[], key: string): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const content = `/**
 * Unobfuscated Reference Signatures
 * 
 * WARNING: This file contains the original unobfuscated signature patterns.
 * This file should NEVER be pushed to a remote repository.
 * Add this file to .gitignore.
 * 
 * Generated with key: ${key}
 */

export const REFERENCE_SIGNATURES = ${JSON.stringify(signatures, null, 2)} as const;

export const OBFUSCATION_KEY = '${key}';
`;
  
  fs.writeFileSync(filePath, content, 'utf-8');
}

async function main() {
  console.log('Generating obfuscated signatures...\n');
  console.log(`Using obfuscation key: ${OBFUSCATION_KEY}\n`);
  
  const signaturesDir = path.join(__dirname, '..', 'signatures');
  const srcDir = path.join(__dirname);
  
  const signatureFiles = [
    'php-signatures.json',
    'js-signatures.json',
  ];
  
  for (const file of signatureFiles) {
    const inputPath = path.join(signaturesDir, file);
    const outputPath = path.join(signaturesDir, file);
    const referencePath = path.join(srcDir, 'reference-signatures.ts');
    
    console.log(`Processing ${file}...`);
    
    const signatureFile: SignatureFile = loadSignatureFile(inputPath);
    
    // Obfuscate the signatures
    const obfuscatedSignatures = obfuscateSignatures(signatureFile.signatures, OBFUSCATION_KEY);
    
    // Create output with obfuscated signatures
    const outputFile: SignatureFile = {
      version: signatureFile.version,
      description: signatureFile.description,
      lastUpdated: new Date().toISOString().split('T')[0],
      signatures: obfuscatedSignatures as any,
    };
    
    // Save obfuscated version (safe to commit)
    saveSignatureFile(outputPath, outputFile);
    console.log(`  - Saved obfuscated: ${outputPath}`);
    
    // Generate reference file (DO NOT COMMIT)
    generateReferenceFile(referencePath, signatureFile.signatures, OBFUSCATION_KEY);
    console.log(`  - Generated reference: ${referencePath}`);
    console.log(`  - Reference file should be added to .gitignore!\n`);
  }
  
  console.log('Done!');
  console.log('\nIMPORTANT:');
  console.log('1. Review the obfuscated signatures in the signatures/ directory');
  console.log('2. The reference-signatures.ts file contains unobfuscated patterns');
  console.log('3. Add "src/reference-signatures.ts" to .gitignore');
  console.log('4. NEVER commit the reference file to a remote repository');
  console.log(`\nObfuscation key for deobfuscation: ${OBFUSCATION_KEY}`);
  console.log('(Store this key securely - needed to decode signatures at runtime)');
}

main().catch(console.error);
