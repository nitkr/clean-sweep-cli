import * as fs from 'fs';
import * as path from 'path';
import { obfuscateSignature } from './signature-obfuscator';

interface Signature {
  id: string;
  name: string;
  description: string;
  severity: string;
  pattern: string;
  type: string;
  category: string;
}

interface SignatureFile {
  version: string;
  description: string;
  lastUpdated: string;
  signatures: Signature[];
}

/**
 * Generate obfuscated signatures file from source signatures
 */
function generateObfuscatedSignatures(): void {
  const sourcePath = path.join(__dirname, '..', 'signatures', 'php-signatures.json');
  const outputPath = path.join(__dirname, '..', 'signatures', 'php-signatures-obfuscated.json');
  const referencePath = path.join(__dirname, '..', 'signatures', 'php-signatures-reference.json');

  if (!fs.existsSync(sourcePath)) {
    console.error('Source signatures file not found:', sourcePath);
    process.exit(1);
  }

  const sourceData: SignatureFile = JSON.parse(fs.readFileSync(sourcePath, 'utf-8'));

  // Create obfuscated version
  const obfuscatedSignatures = sourceData.signatures.map(sig => ({
    ...sig,
    pattern: obfuscateSignature(sig.pattern),
  }));

  const obfuscatedData: SignatureFile = {
    version: sourceData.version,
    description: 'Obfuscated PHP malware signatures for Clean Sweep CLI',
    lastUpdated: new Date().toISOString(),
    signatures: obfuscatedSignatures,
  };

  // Write obfuscated version
  fs.writeFileSync(outputPath, JSON.stringify(obfuscatedData, null, 2), 'utf-8');
  console.log('Generated obfuscated signatures:', outputPath);

  // Write reference version (non-obfuscated copy for development)
  fs.writeFileSync(referencePath, JSON.stringify(sourceData, null, 2), 'utf-8');
  console.log('Generated reference signatures:', referencePath);
}

// Run if called directly
if (require.main === module) {
  generateObfuscatedSignatures();
}

export { generateObfuscatedSignatures };
