import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import * as path from 'path';
import * as fs from 'fs';
import { findUnknownFiles, isWordPressInstallation } from '../src/wp-file-detector';

describe('WordPress File Detector', () => {
  describe('findUnknownFiles', () => {
    const testDir = path.join(__dirname, 'temp-wp-test');

    beforeAll(() => {
      fs.mkdirSync(testDir, { recursive: true });
      fs.mkdirSync(path.join(testDir, 'wp-admin'), { recursive: true });
      fs.mkdirSync(path.join(testDir, 'wp-includes'), { recursive: true });
      fs.mkdirSync(path.join(testDir, 'wp-content', 'themes', 'mytheme'), { recursive: true });
      fs.mkdirSync(path.join(testDir, 'wp-content', 'plugins', 'myplugin'), { recursive: true });
      fs.mkdirSync(path.join(testDir, 'uploads'), { recursive: true });

      fs.writeFileSync(path.join(testDir, 'wp-admin', 'index.php'), '<?php // WP admin');
      fs.writeFileSync(path.join(testDir, 'wp-includes', 'functions.php'), '<?php // WP functions');
      fs.writeFileSync(path.join(testDir, 'wp-login.php'), '<?php // WP login');
      fs.writeFileSync(path.join(testDir, 'index.php'), '<?php // WP index');
      fs.writeFileSync(path.join(testDir, 'wp-config.php'), '<?php // WP config');
      fs.writeFileSync(path.join(testDir, 'wp-content', 'themes', 'mytheme', 'style.css'), 'body {}');
      fs.writeFileSync(path.join(testDir, 'wp-content', 'plugins', 'myplugin', 'main.php'), '<?php // Plugin');
      fs.writeFileSync(path.join(testDir, 'custom-file.php'), '<?php // Custom file');
      fs.writeFileSync(path.join(testDir, 'uploads', 'image.jpg'), 'binary data');
    });

    afterAll(() => {
      fs.rmSync(testDir, { recursive: true, force: true });
    });

    it('should return result with count and files array', async () => {
      const result = await findUnknownFiles(testDir);
      expect(result).toHaveProperty('count');
      expect(result).toHaveProperty('files');
      expect(Array.isArray(result.files)).toBe(true);
    });

    it('should exclude WordPress core files', async () => {
      const result = await findUnknownFiles(testDir);
      const files = result.files.join(',');
      expect(files).not.toContain('wp-admin/index.php');
      expect(files).not.toContain('wp-includes/functions.php');
      expect(files).not.toContain('wp-login.php');
      expect(files).not.toContain('index.php');
    });

    it('should include non-core files', async () => {
      const result = await findUnknownFiles(testDir, ['**/node_modules/**', '**/dist/**', '**/uploads/**', '**/wp-content/**']);
      const files = result.files.join(',');
      expect(files).toContain('custom-file.php');
    });

    it('should return correct count', async () => {
      const result = await findUnknownFiles(testDir);
      expect(result.count).toBe(result.files.length);
    });

    it('should accept custom ignore patterns', async () => {
      const result = await findUnknownFiles(testDir, ['**/wp-content/**', '**/uploads/**']);
      expect(result.count).toBe(1);
      expect(result.files).toContain('custom-file.php');
    });

    it('should handle empty directory', async () => {
      const emptyDir = path.join(__dirname, 'temp-empty-test');
      fs.mkdirSync(emptyDir, { recursive: true });
      const result = await findUnknownFiles(emptyDir);
      fs.rmSync(emptyDir, { recursive: true, force: true });
      expect(result.count).toBe(0);
      expect(result.files).toHaveLength(0);
    });

    it('should return 0 unknown when only core files exist', async () => {
      const coreOnlyDir = path.join(__dirname, 'temp-core-only');
      fs.mkdirSync(coreOnlyDir, { recursive: true });
      fs.mkdirSync(path.join(coreOnlyDir, 'wp-admin'), { recursive: true });
      fs.mkdirSync(path.join(coreOnlyDir, 'wp-includes'), { recursive: true });
      fs.writeFileSync(path.join(coreOnlyDir, 'wp-admin', 'index.php'), '<?php');
      fs.writeFileSync(path.join(coreOnlyDir, 'wp-includes', 'functions.php'), '<?php');
      fs.writeFileSync(path.join(coreOnlyDir, 'wp-login.php'), '<?php');
      fs.writeFileSync(path.join(coreOnlyDir, 'wp-config.php'), '<?php');
      fs.writeFileSync(path.join(coreOnlyDir, 'index.php'), '<?php');

      const result = await findUnknownFiles(coreOnlyDir);
      fs.rmSync(coreOnlyDir, { recursive: true, force: true });
      expect(result.count).toBe(0);
      expect(result.files).toHaveLength(0);
    });

    it('should handle mixed core and non-core files correctly', async () => {
      const mixedDir = path.join(__dirname, 'temp-mixed');
      fs.mkdirSync(mixedDir, { recursive: true });
      fs.mkdirSync(path.join(mixedDir, 'wp-admin'), { recursive: true });
      fs.mkdirSync(path.join(mixedDir, 'wp-includes'), { recursive: true });
      fs.mkdirSync(path.join(mixedDir, 'themes'), { recursive: true });
      fs.mkdirSync(path.join(mixedDir, 'plugins'), { recursive: true });

      fs.writeFileSync(path.join(mixedDir, 'wp-admin', 'index.php'), '<?php');
      fs.writeFileSync(path.join(mixedDir, 'wp-includes', 'functions.php'), '<?php');
      fs.writeFileSync(path.join(mixedDir, 'wp-login.php'), '<?php');
      fs.writeFileSync(path.join(mixedDir, 'wp-config.php'), '<?php');
      fs.writeFileSync(path.join(mixedDir, 'index.php'), '<?php');
      fs.writeFileSync(path.join(mixedDir, 'custom.php'), '<?php');
      fs.writeFileSync(path.join(mixedDir, 'themes', 'mytheme.php'), '<?php');
      fs.writeFileSync(path.join(mixedDir, 'plugins', 'myplugin.php'), '<?php');

      const result = await findUnknownFiles(mixedDir);
      fs.rmSync(mixedDir, { recursive: true, force: true });
      expect(result.count).toBe(3);
      expect(result.files).toContain('custom.php');
      expect(result.files).toContain('plugins/myplugin.php');
      expect(result.files).toContain('themes/mytheme.php');
      expect(result.files).not.toContain('wp-admin/index.php');
      expect(result.files).not.toContain('wp-includes/functions.php');
    });

    it('should handle custom ignore patterns correctly', async () => {
      const customIgnoreDir = path.join(__dirname, 'temp-custom-ignore');
      fs.mkdirSync(customIgnoreDir, { recursive: true });
      fs.mkdirSync(path.join(customIgnoreDir, 'wp-admin'), { recursive: true });
      fs.mkdirSync(path.join(customIgnoreDir, 'wp-includes'), { recursive: true });
      fs.mkdirSync(path.join(customIgnoreDir, 'cache'), { recursive: true });
      fs.mkdirSync(path.join(customIgnoreDir, 'temp'), { recursive: true });

      fs.writeFileSync(path.join(customIgnoreDir, 'wp-admin', 'index.php'), '<?php');
      fs.writeFileSync(path.join(customIgnoreDir, 'wp-includes', 'functions.php'), '<?php');
      fs.writeFileSync(path.join(customIgnoreDir, 'custom.php'), '<?php');
      fs.writeFileSync(path.join(customIgnoreDir, 'cache', 'cached.php'), '<?php');
      fs.writeFileSync(path.join(customIgnoreDir, 'temp', 'tmp.php'), '<?php');

      const result = await findUnknownFiles(customIgnoreDir, ['**/cache/**', '**/temp/**']);
      fs.rmSync(customIgnoreDir, { recursive: true, force: true });
      expect(result.files).toContain('custom.php');
      expect(result.files).not.toContain('cache/cached.php');
      expect(result.files).not.toContain('temp/tmp.php');
    });

    it('should handle deeply nested non-core files', async () => {
      const nestedDir = path.join(__dirname, 'temp-nested');
      fs.mkdirSync(nestedDir, { recursive: true });
      fs.mkdirSync(path.join(nestedDir, 'wp-admin'), { recursive: true });
      fs.mkdirSync(path.join(nestedDir, 'wp-includes'), { recursive: true });
      fs.mkdirSync(path.join(nestedDir, 'a', 'b', 'c', 'd'), { recursive: true });

      fs.writeFileSync(path.join(nestedDir, 'wp-admin', 'index.php'), '<?php');
      fs.writeFileSync(path.join(nestedDir, 'wp-includes', 'functions.php'), '<?php');
      fs.writeFileSync(path.join(nestedDir, 'a', 'b', 'c', 'd', 'deep.php'), '<?php');

      const result = await findUnknownFiles(nestedDir);
      fs.rmSync(nestedDir, { recursive: true, force: true });
      expect(result.files).toContain('a/b/c/d/deep.php');
    });
  });

  describe('isWordPressInstallation', () => {
    it('should return true for valid WordPress installation', () => {
      const wpDir = path.join(__dirname, 'temp-wp-install');
      fs.mkdirSync(wpDir, { recursive: true });
      fs.mkdirSync(path.join(wpDir, 'wp-admin'), { recursive: true });
      fs.mkdirSync(path.join(wpDir, 'wp-includes'), { recursive: true });
      fs.writeFileSync(path.join(wpDir, 'wp-config.php'), '<?php');
      fs.writeFileSync(path.join(wpDir, 'wp-login.php'), '<?php');

      const result = isWordPressInstallation(wpDir);
      fs.rmSync(wpDir, { recursive: true, force: true });
      expect(result).toBe(true);
    });

    it('should return false when wp-admin is missing', () => {
      const dir = path.join(__dirname, 'temp-no-wpadmin');
      fs.mkdirSync(dir, { recursive: true });
      fs.mkdirSync(path.join(dir, 'wp-includes'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'wp-config.php'), '<?php');
      fs.writeFileSync(path.join(dir, 'wp-login.php'), '<?php');

      const result = isWordPressInstallation(dir);
      fs.rmSync(dir, { recursive: true, force: true });
      expect(result).toBe(false);
    });

    it('should return false when wp-includes is missing', () => {
      const dir = path.join(__dirname, 'temp-no-wpincludes');
      fs.mkdirSync(dir, { recursive: true });
      fs.mkdirSync(path.join(dir, 'wp-admin'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'wp-config.php'), '<?php');
      fs.writeFileSync(path.join(dir, 'wp-login.php'), '<?php');

      const result = isWordPressInstallation(dir);
      fs.rmSync(dir, { recursive: true, force: true });
      expect(result).toBe(false);
    });

    it('should return false when wp-config.php is missing', () => {
      const dir = path.join(__dirname, 'temp-no-config');
      fs.mkdirSync(dir, { recursive: true });
      fs.mkdirSync(path.join(dir, 'wp-admin'), { recursive: true });
      fs.mkdirSync(path.join(dir, 'wp-includes'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'wp-login.php'), '<?php');

      const result = isWordPressInstallation(dir);
      fs.rmSync(dir, { recursive: true, force: true });
      expect(result).toBe(false);
    });

    it('should return false when wp-login.php is missing', () => {
      const dir = path.join(__dirname, 'temp-no-login');
      fs.mkdirSync(dir, { recursive: true });
      fs.mkdirSync(path.join(dir, 'wp-admin'), { recursive: true });
      fs.mkdirSync(path.join(dir, 'wp-includes'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'wp-config.php'), '<?php');

      const result = isWordPressInstallation(dir);
      fs.rmSync(dir, { recursive: true, force: true });
      expect(result).toBe(false);
    });

    it('should return false for non-WP directory', () => {
      const dir = path.join(__dirname, 'temp-not-wp');
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, 'file.txt'), 'content');

      const result = isWordPressInstallation(dir);
      fs.rmSync(dir, { recursive: true, force: true });
      expect(result).toBe(false);
    });

    it('should return false for empty directory', () => {
      const dir = path.join(__dirname, 'temp-empty-dir');
      fs.mkdirSync(dir, { recursive: true });

      const result = isWordPressInstallation(dir);
      fs.rmSync(dir, { recursive: true, force: true });
      expect(result).toBe(false);
    });

    it('should return false when only wp-content exists', () => {
      const dir = path.join(__dirname, 'temp-only-wpcontent');
      fs.mkdirSync(path.join(dir, 'wp-content', 'themes', 'mytheme'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'wp-content', 'themes', 'mytheme', 'style.css'), 'body {}');

      const result = isWordPressInstallation(dir);
      fs.rmSync(dir, { recursive: true, force: true });
      expect(result).toBe(false);
    });

    it('should return false when only wp-admin exists', () => {
      const dir = path.join(__dirname, 'temp-only-wpadmin');
      fs.mkdirSync(dir, { recursive: true });
      fs.mkdirSync(path.join(dir, 'wp-admin'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'wp-admin', 'index.php'), '<?php');

      const result = isWordPressInstallation(dir);
      fs.rmSync(dir, { recursive: true, force: true });
      expect(result).toBe(false);
    });

    it('should return false when only wp-includes exists', () => {
      const dir = path.join(__dirname, 'temp-only-wpincludes');
      fs.mkdirSync(dir, { recursive: true });
      fs.mkdirSync(path.join(dir, 'wp-includes'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'wp-includes', 'functions.php'), '<?php');

      const result = isWordPressInstallation(dir);
      fs.rmSync(dir, { recursive: true, force: true });
      expect(result).toBe(false);
    });

    it('should return false when only some required files exist', () => {
      const dir = path.join(__dirname, 'temp-partial-files');
      fs.mkdirSync(dir, { recursive: true });
      fs.mkdirSync(path.join(dir, 'wp-admin'), { recursive: true });
      fs.mkdirSync(path.join(dir, 'wp-includes'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'wp-admin', 'index.php'), '<?php');
      fs.writeFileSync(path.join(dir, 'wp-includes', 'functions.php'), '<?php');

      const result = isWordPressInstallation(dir);
      fs.rmSync(dir, { recursive: true, force: true });
      expect(result).toBe(false);
    });

    it('should return false when directories exist but required files missing', () => {
      const dir = path.join(__dirname, 'temp-dirs-no-files');
      fs.mkdirSync(dir, { recursive: true });
      fs.mkdirSync(path.join(dir, 'wp-admin'), { recursive: true });
      fs.mkdirSync(path.join(dir, 'wp-includes'), { recursive: true });
      fs.mkdirSync(path.join(dir, 'wp-content'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'index.php'), '<?php');

      const result = isWordPressInstallation(dir);
      fs.rmSync(dir, { recursive: true, force: true });
      expect(result).toBe(false);
    });
  });
});
