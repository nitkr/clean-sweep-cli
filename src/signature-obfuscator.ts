import * as crypto from 'crypto';

/**
 * Obfuscate a signature pattern using XOR + Base64 encoding
 * This prevents simple string-matching or easy decoding of signatures
 */
export function obfuscateSignature(pattern: string, key: string = 'clean-sweep-cli'): string {
  const xorKey = crypto.createHash('sha256').update(key).digest();
  const patternBytes = Buffer.from(pattern, 'utf-8');
  const obfuscated = Buffer.alloc(patternBytes.length);
  
  for (let i = 0; i < patternBytes.length; i++) {
    obfuscated[i] = patternBytes[i] ^ xorKey[i % xorKey.length];
  }
  
  return Buffer.concat([
    Buffer.from('obf:'),
    Buffer.from(xorKey.toString('hex').substring(0, 8)),
    Buffer.from(':'),
    Buffer.from(obfuscated.toString('base64'))
  ]).toString('base64');
}

/**
 * Deobfuscate a signature pattern
 */
export function deobfuscateSignature(obfuscated: string): string {
  try {
    const decoded = Buffer.from(obfuscated, 'base64').toString('utf-8');
    const parts = decoded.split(':');
    
    if (parts[0] !== 'obf') {
      // Not obfuscated, return as-is
      return obfuscated;
    }
    
    const xorKeyHex = parts[1];
    const encodedPattern = parts[2];
    const xorKey = Buffer.from(xorKeyHex, 'hex');
    const patternBytes = Buffer.from(encodedPattern, 'base64');
    const deobfuscated = Buffer.alloc(patternBytes.length);
    
    for (let i = 0; i < patternBytes.length; i++) {
      deobfuscated[i] = patternBytes[i] ^ xorKey[i % xorKey.length];
    }
    
    return deobfuscated.toString('utf-8');
  } catch {
    // If deobfuscation fails, return as-is
    return obfuscated;
  }
}

/**
 * Check if a signature is obfuscated
 */
export function isObfuscated(pattern: string): boolean {
  try {
    const decoded = Buffer.from(pattern, 'base64').toString('utf-8');
    return decoded.startsWith('obf:');
  } catch {
    return false;
  }
}

/**
 * Generate a secure key for signature obfuscation
 */
export function generateSignatureKey(): string {
  return crypto.randomBytes(32).toString('hex');
}
