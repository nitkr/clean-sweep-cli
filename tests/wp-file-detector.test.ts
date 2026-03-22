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
  });
});
