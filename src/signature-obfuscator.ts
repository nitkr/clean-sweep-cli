/**
 * Signature Obfuscator Module
 * 
 * Provides XOR + Base64 encoding to obfuscate malware signature patterns.
 * This prevents attackers from easily detecting what patterns we're scanning for.
 * 
 * IMPORTANT: The unobfuscated reference file should NEVER be pushed to remote repositories.
 * Add the unobfuscated signatures file to .gitignore.
 */

export interface ObfuscatedSignature {
  id: string;
  obfuscatedPattern: string;
  deobfuscationKey: string;
  originalType?: string;
  severity?: string;
}

/**
 * XORs each character of the input string with the given key.
 * The key is repeated to match the length of the input.
 */
function xorString(input: string, key: string): string {
  let result = '';
  for (let i = 0; i < input.length; i++) {
    const charCode = input.charCodeAt(i) ^ key.charCodeAt(i % key.length);
    result += String.fromCharCode(charCode);
  }
  return result;
}

/**
 * Converts a buffer to a base64 string.
 */
function toBase64(buffer: string): string {
  // Handle Unicode characters properly
  const bytes = new Uint8Array(buffer.length);
  for (let i = 0; i < buffer.length; i++) {
    bytes[i] = buffer.charCodeAt(i);
  }
  return Buffer.from(bytes).toString('base64');
}

/**
 * Decodes a base64 string back to a buffer.
 */
function fromBase64(base64: string): string {
  const bytes = Buffer.from(base64, 'base64');
  let result = '';
  for (let i = 0; i < bytes.length; i++) {
    result += String.fromCharCode(bytes[i]);
  }
  return result;
}

/**
 * Obfuscates a signature pattern using XOR + Base64 encoding.
 * 
 * @param pattern - The regex pattern string to obfuscate
 * @param key - Secret key for XOR operation (should be at least 8 characters)
 * @returns Object containing obfuscated pattern and key for deobfuscation
 */
export function obfuscatePattern(pattern: string, key: string): { obfuscated: string; key: string } {
  const xored = xorString(pattern, key);
  const obfuscated = toBase64(xored);
  return {
    obfuscated,
    key,
  };
}

/**
 * Deobfuscates a signature pattern that was obfuscated with obfuscatePattern.
 * 
 * @param obfuscatedPattern - Base64-encoded XORed pattern
 * @param key - Secret key used during obfuscation
 * @returns The original pattern string
 */
export function deobfuscatePattern(obfuscatedPattern: string, key: string): string {
  const decoded = fromBase64(obfuscatedPattern);
  return xorString(decoded, key);
}

/**
 * Obfuscates a batch of signatures for storage in production.
 * 
 * @param signatures - Array of signature objects with pattern field
 * @param key - Secret key for XOR operation
 * @returns Array of obfuscated signatures ready for storage
 */
export function obfuscateSignatures<T extends { id: string; pattern?: string; type?: string; severity?: string }>(
  signatures: T[],
  key: string
): (Omit<T, 'pattern'> & ObfuscatedSignature)[] {
  return signatures.map(sig => {
    if (!sig.pattern) {
      const { pattern, ...sigWithoutPattern } = sig;
      return {
        ...sigWithoutPattern,
        obfuscatedPattern: '',
        deobfuscationKey: key,
      } as Omit<T, 'pattern'> & ObfuscatedSignature;
    }
    
    const { obfuscated } = obfuscatePattern(sig.pattern, key);
    const { pattern, ...sigWithoutPattern } = sig;
    return {
      ...sigWithoutPattern,
      obfuscatedPattern: obfuscated,
      deobfuscationKey: key,
    };
  });
}

/**
 * Deobfuscates a batch of signatures from storage.
 * 
 * @param signatures - Array of obfuscated signature objects
 * @returns Array of signatures with pattern field restored
 */
export function deobfuscateSignatures<T extends { id: string; obfuscatedPattern?: string; deobfuscationKey?: string; pattern?: string }>(
  signatures: T[]
): (Omit<T, 'obfuscatedPattern' | 'deobfuscationKey'> & { pattern: string })[] {
  return signatures.map(sig => {
    if (!sig.obfuscatedPattern || !sig.deobfuscationKey) {
      // If not obfuscated, return as-is (for backwards compatibility)
      return {
        ...sig,
        pattern: (sig as any).pattern || '',
      } as Omit<T, 'obfuscatedPattern' | 'deobfuscationKey'> & { pattern: string };
    }
    
    const pattern = deobfuscatePattern(sig.obfuscatedPattern, sig.deobfuscationKey);
    const { obfuscatedPattern, deobfuscationKey, ...rest } = sig;
    return {
      ...rest,
      pattern,
    } as Omit<T, 'obfuscatedPattern' | 'deobfuscationKey'> & { pattern: string };
  });
}

/**
 * Generates a random key of specified length for signature obfuscation.
 */
export function generateKey(length: number = 16): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
  let key = '';
  for (let i = 0; i < length; i++) {
    key += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return key;
}

/**
 * Validates that a deobfuscated pattern is a valid regex.
 */
export function isValidPattern(pattern: string): boolean {
  try {
    new RegExp(pattern);
    return true;
  } catch {
    return false;
  }
}
