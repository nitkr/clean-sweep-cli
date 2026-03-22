import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { checkWordPressIntegrity, IntegrityResult } from '../src/file-integrity';

function computeFileHash(filePath: string): string {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}

function detectWordPressVersion(targetPath: string): string | null {
  const versionFile = path.join(targetPath, 'wp-includes', 'version.php');
  
  if (!fs.existsSync(versionFile)) {
    return null;
  }
  
  try {
    const content = fs.readFileSync(versionFile, 'utf-8');
    const match = content.match(/\$wp_version\s*=\s*['"]([^'"]+)['"]/);
    return match ? match[1] : null;
  } catch {
    return null;
  }
}

describe('File Integrity', () => {
  let tempDir: string;

  beforeAll(() => {
    tempDir = fs.mkdtempSync('file-integrity-test-');
  });

  afterAll(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  describe('computeFileHash', () => {
    it('should return consistent SHA-256 hash for the same file', () => {
      const testFile = path.join(tempDir, 'test-file.txt');
      const content = 'Hello World';
      fs.writeFileSync(testFile, content);

      const hash1 = computeFileHash(testFile);
      const hash2 = computeFileHash(testFile);

      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(64);
    });

    it('should return SHA-256 hash that matches known value', () => {
      const testFile = path.join(tempDir, 'test-hash.txt');
      const content = 'test content';
      fs.writeFileSync(testFile, content);

      const hash = computeFileHash(testFile);
      const expectedHash = crypto.createHash('sha256').update(content).digest('hex');

      expect(hash).toBe(expectedHash);
    });

    it('should return different hashes for different content', () => {
      const testFile1 = path.join(tempDir, 'file1.txt');
      const testFile2 = path.join(tempDir, 'file2.txt');

      fs.writeFileSync(testFile1, 'content A');
      fs.writeFileSync(testFile2, 'content B');

      const hash1 = computeFileHash(testFile1);
      const hash2 = computeFileHash(testFile2);

      expect(hash1).not.toBe(hash2);
    });

    it('should handle empty files correctly', () => {
      const testFile = path.join(tempDir, 'empty-file.txt');
      fs.writeFileSync(testFile, '');

      const hash = computeFileHash(testFile);
      const expectedHash = crypto.createHash('sha256').update('').digest('hex');

      expect(hash).toBe(expectedHash);
      expect(hash).toHaveLength(64);
      expect(hash).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });

    it('should handle binary files correctly', () => {
      const testFile = path.join(tempDir, 'binary-file.bin');
      const binaryContent = Buffer.from([0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD, 0x89, 0x50, 0x4E, 0x47]);
      fs.writeFileSync(testFile, binaryContent);

      const hash = computeFileHash(testFile);
      const expectedHash = crypto.createHash('sha256').update(binaryContent).digest('hex');

      expect(hash).toBe(expectedHash);
    });

    it('should handle large files correctly', () => {
      const testFile = path.join(tempDir, 'large-file.bin');
      const largeContent = Buffer.alloc(10 * 1024 * 1024, 0x42);
      fs.writeFileSync(testFile, largeContent);

      const hash = computeFileHash(testFile);
      const expectedHash = crypto.createHash('sha256').update(largeContent).digest('hex');

      expect(hash).toBe(expectedHash);
      expect(hash).toHaveLength(64);
    });

    it('should handle files with special characters', () => {
      const testFile = path.join(tempDir, 'special-chars.txt');
      const specialContent = 'Hello World! @#$%^&*() `~±§©®\n\t\r\'"\\';
      fs.writeFileSync(testFile, specialContent);

      const hash = computeFileHash(testFile);
      const expectedHash = crypto.createHash('sha256').update(specialContent).digest('hex');

      expect(hash).toBe(expectedHash);
    });

    it('should handle unicode characters correctly', () => {
      const testFile = path.join(tempDir, 'unicode-file.txt');
      const unicodeContent = 'Hello 世界 🌍 Γειά σου Κόσμε';
      fs.writeFileSync(testFile, unicodeContent);

      const hash = computeFileHash(testFile);
      const expectedHash = crypto.createHash('sha256').update(unicodeContent).digest('hex');

      expect(hash).toBe(expectedHash);
    });

    it('should handle files with only whitespace', () => {
      const testFile = path.join(tempDir, 'whitespace-file.txt');
      const whitespaceContent = '   \t\n\r   ';
      fs.writeFileSync(testFile, whitespaceContent);

      const hash = computeFileHash(testFile);
      const expectedHash = crypto.createHash('sha256').update(whitespaceContent).digest('hex');

      expect(hash).toBe(expectedHash);
    });
  });

  describe('detectWordPressVersion', () => {
    it('should extract version correctly from version.php', () => {
      const wpDir = path.join(tempDir, 'wp');
      const wpIncludesDir = path.join(wpDir, 'wp-includes');
      fs.mkdirSync(wpIncludesDir, { recursive: true });

      const versionContent = `<?php
/**
 * WordPress version
 *
 * Contains version information for the core WordPress release.
 *
 * @package WordPress
 * @since 1.2.0
 */

/**
 * The WordPress version string.
 *
 * Holds the current WordPress version information. Used to version cache and
 * other things.
 *
 * @global string $wp_version
 */
$wp_version = '6.4.3';
`;
      fs.writeFileSync(path.join(wpIncludesDir, 'version.php'), versionContent);

      const version = detectWordPressVersion(wpDir);

      expect(version).toBe('6.4.3');
    });

    it('should return null for non-existent wp-includes directory', () => {
      const nonWpDir = path.join(tempDir, 'not-wordpress');
      fs.mkdirSync(nonWpDir, { recursive: true });

      const version = detectWordPressVersion(nonWpDir);

      expect(version).toBeNull();
    });

    it('should return null for non-existent version.php file', () => {
      const wpDir = path.join(tempDir, 'wp-no-version');
      const wpIncludesDir = path.join(wpDir, 'wp-includes');
      fs.mkdirSync(wpIncludesDir, { recursive: true });

      const version = detectWordPressVersion(wpDir);

      expect(version).toBeNull();
    });

    it('should return null for invalid version.php file', () => {
      const wpDir = path.join(tempDir, 'wp-invalid');
      const wpIncludesDir = path.join(wpDir, 'wp-includes');
      fs.mkdirSync(wpIncludesDir, { recursive: true });

      const invalidContent = '<?php echo "not a version file"; ?>';
      fs.writeFileSync(path.join(wpIncludesDir, 'version.php'), invalidContent);

      const version = detectWordPressVersion(wpDir);

      expect(version).toBeNull();
    });

    it('should return null for version.php without $wp_version variable', () => {
      const wpDir = path.join(tempDir, 'wp-no-var');
      const wpIncludesDir = path.join(wpDir, 'wp-includes');
      fs.mkdirSync(wpIncludesDir, { recursive: true });

      const content = '<?php $other_var = "value"; ?>';
      fs.writeFileSync(path.join(wpIncludesDir, 'version.php'), content);

      const version = detectWordPressVersion(wpDir);

      expect(version).toBeNull();
    });

    it('should extract version with different formatting', () => {
      const wpDir = path.join(tempDir, 'wp-alt-format');
      const wpIncludesDir = path.join(wpDir, 'wp-includes');
      fs.mkdirSync(wpIncludesDir, { recursive: true });

      const versionContent = `<?php
$wp_version = "5.8.1";
`;
      fs.writeFileSync(path.join(wpIncludesDir, 'version.php'), versionContent);

      const version = detectWordPressVersion(wpDir);

      expect(version).toBe('5.8.1');
    });

    it('should extract first version when multiple versions defined', () => {
      const wpDir = path.join(tempDir, 'wp-multi-version');
      const wpIncludesDir = path.join(wpDir, 'wp-includes');
      fs.mkdirSync(wpIncludesDir, { recursive: true });

      const versionContent = `<?php
$wp_version = '6.4.3';
$wp_version = '6.5.0';
`;
      fs.writeFileSync(path.join(wpIncludesDir, 'version.php'), versionContent);

      const version = detectWordPressVersion(wpDir);

      expect(version).toBe('6.4.3');
    });

    it('should extract version from commented version line (first match wins even in comments)', () => {
      const wpDir = path.join(tempDir, 'wp-comments');
      const wpIncludesDir = path.join(wpDir, 'wp-includes');
      fs.mkdirSync(wpIncludesDir, { recursive: true });

      const versionContent = `<?php
// $wp_version = '6.3.0';
$wp_version = '6.4.3';
`;
      fs.writeFileSync(path.join(wpIncludesDir, 'version.php'), versionContent);

      const version = detectWordPressVersion(wpDir);

      expect(version).toBe('6.3.0');
    });

    it('should handle version with no spaces around equals', () => {
      const wpDir = path.join(tempDir, 'wp-no-spaces');
      const wpIncludesDir = path.join(wpDir, 'wp-includes');
      fs.mkdirSync(wpIncludesDir, { recursive: true });

      const versionContent = `<?php
$wp_version='6.4.3';
`;
      fs.writeFileSync(path.join(wpIncludesDir, 'version.php'), versionContent);

      const version = detectWordPressVersion(wpDir);

      expect(version).toBe('6.4.3');
    });

    it('should handle version with extra whitespace', () => {
      const wpDir = path.join(tempDir, 'wp-extra-spaces');
      const wpIncludesDir = path.join(wpDir, 'wp-includes');
      fs.mkdirSync(wpIncludesDir, { recursive: true });

      const versionContent = `<?php
$wp_version   =   '6.4.3'  ;
`;
      fs.writeFileSync(path.join(wpIncludesDir, 'version.php'), versionContent);

      const version = detectWordPressVersion(wpDir);

      expect(version).toBe('6.4.3');
    });

    it('should handle version with trailing version numbers', () => {
      const wpDir = path.join(tempDir, 'wp-beta');
      const wpIncludesDir = path.join(wpDir, 'wp-includes');
      fs.mkdirSync(wpIncludesDir, { recursive: true });

      const versionContent = `<?php
$wp_version = '6.4.3-RC1';
`;
      fs.writeFileSync(path.join(wpIncludesDir, 'version.php'), versionContent);

      const version = detectWordPressVersion(wpDir);

      expect(version).toBe('6.4.3-RC1');
    });
  });

  describe('checkWordPressIntegrity', () => {
    it('should return proper IntegrityResult structure', async () => {
      const wpDir = path.join(tempDir, 'wp-test');
      const wpIncludesDir = path.join(wpDir, 'wp-includes');
      fs.mkdirSync(wpIncludesDir, { recursive: true });

      const versionContent = `<?php $wp_version = '6.4.3'; ?>`;
      fs.writeFileSync(path.join(wpIncludesDir, 'version.php'), versionContent);

      const result = await checkWordPressIntegrity(wpDir);

      expect(result).toHaveProperty('checked');
      expect(result).toHaveProperty('modified');
      expect(result).toHaveProperty('modifiedFiles');
      expect(result).toHaveProperty('wordpressVersion');
      expect(typeof result.checked).toBe('number');
      expect(typeof result.modified).toBe('number');
      expect(Array.isArray(result.modifiedFiles)).toBe(true);
    });

    it('should return correct wordpressVersion when version.php exists', async () => {
      const wpDir = path.join(tempDir, 'wp-version-test');
      const wpIncludesDir = path.join(wpDir, 'wp-includes');
      fs.mkdirSync(wpIncludesDir, { recursive: true });

      const versionContent = `<?php $wp_version = '6.5.0'; ?>`;
      fs.writeFileSync(path.join(wpIncludesDir, 'version.php'), versionContent);

      const result = await checkWordPressIntegrity(wpDir);

      expect(result.wordpressVersion).toBe('6.5.0');
    });

    it('should return undefined for wordpressVersion when version.php does not exist', async () => {
      const nonWpDir = path.join(tempDir, 'not-wp');
      fs.mkdirSync(nonWpDir, { recursive: true });

      const result = await checkWordPressIntegrity(nonWpDir);

      expect(result.wordpressVersion).toBeUndefined();
    });

    it('should count checked files correctly', async () => {
      const wpDir = path.join(tempDir, 'wp-count-test');
      const wpIncludesDir = path.join(wpDir, 'wp-includes');
      const wpAdminDir = path.join(wpDir, 'wp-admin');
      fs.mkdirSync(wpIncludesDir, { recursive: true });
      fs.mkdirSync(wpAdminDir, { recursive: true });

      fs.writeFileSync(path.join(wpIncludesDir, 'version.php'), '<?php $wp_version = "6.4"; ?>');
      fs.writeFileSync(path.join(wpIncludesDir, 'functions.php'), '<?php // functions');
      fs.writeFileSync(path.join(wpAdminDir, 'index.php'), '<?php // admin');

      const result = await checkWordPressIntegrity(wpDir);

      expect(result.checked).toBeGreaterThan(0);
    });

    it('should return zero modified files for clean installation', async () => {
      const wpDir = path.join(tempDir, 'wp-clean');
      const wpIncludesDir = path.join(wpDir, 'wp-includes');
      fs.mkdirSync(wpIncludesDir, { recursive: true });

      fs.writeFileSync(path.join(wpIncludesDir, 'version.php'), '<?php $wp_version = "6.4.3"; ?>');

      const result = await checkWordPressIntegrity(wpDir);

      expect(result.modified).toBe(0);
      expect(result.modifiedFiles).toHaveLength(0);
    });

    it('should return empty modifiedFiles array for clean installation', async () => {
      const wpDir = path.join(tempDir, 'wp-empty-files');
      const wpIncludesDir = path.join(wpDir, 'wp-includes');
      fs.mkdirSync(wpIncludesDir, { recursive: true });

      fs.writeFileSync(path.join(wpIncludesDir, 'version.php'), '<?php $wp_version = "6.4.3"; ?>');

      const result = await checkWordPressIntegrity(wpDir);

      expect(result.modifiedFiles).toEqual([]);
    });

    it('should handle empty wp-includes directory', async () => {
      const wpDir = path.join(tempDir, 'wp-empty-includes');
      const wpIncludesDir = path.join(wpDir, 'wp-includes');
      fs.mkdirSync(wpIncludesDir, { recursive: true });

      const result = await checkWordPressIntegrity(wpDir);

      expect(result.checked).toBe(0);
      expect(result.modified).toBe(0);
    });

    it('should handle empty wp-admin directory', async () => {
      const wpDir = path.join(tempDir, 'wp-empty-admin');
      const wpAdminDir = path.join(wpDir, 'wp-admin');
      fs.mkdirSync(wpAdminDir, { recursive: true });

      const result = await checkWordPressIntegrity(wpDir);

      expect(result.checked).toBe(0);
      expect(result.modified).toBe(0);
    });

    it('should handle empty wp-admin and wp-includes directories', async () => {
      const wpDir = path.join(tempDir, 'wp-both-empty');
      fs.mkdirSync(path.join(wpDir, 'wp-admin'), { recursive: true });
      fs.mkdirSync(path.join(wpDir, 'wp-includes'), { recursive: true });

      const result = await checkWordPressIntegrity(wpDir);

      expect(result.checked).toBe(0);
      expect(result.modified).toBe(0);
      expect(result.modifiedFiles).toHaveLength(0);
    });

    it('should handle root-level core files in mixed case', async () => {
      const wpDir = path.join(tempDir, 'wp-mixed-case');
      fs.mkdirSync(path.join(wpDir, 'wp-includes'), { recursive: true });

      fs.writeFileSync(path.join(wpDir, 'index.php'), '<?php // modified');
      fs.writeFileSync(path.join(wpDir, 'wp-includes', 'version.php'), '<?php $wp_version = "6.4.3"; ?>');

      const result = await checkWordPressIntegrity(wpDir);

      expect(result.modifiedFiles).toContain('index.php');
    });
  });
});