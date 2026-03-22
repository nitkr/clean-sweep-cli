import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { createBackup, copyRecursiveSync, createPluginBackup } from '../src/backup';

describe('Backup Module', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'backup-test-'));
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('copyRecursiveSync', () => {
    it('should copy a single file', () => {
      const srcDir = path.join(tempDir, 'src');
      const destDir = path.join(tempDir, 'dest');
      fs.mkdirSync(srcDir);
      fs.writeFileSync(path.join(srcDir, 'file.txt'), 'test content');

      copyRecursiveSync(srcDir, destDir);

      expect(fs.existsSync(path.join(destDir, 'file.txt'))).toBe(true);
      expect(fs.readFileSync(path.join(destDir, 'file.txt'), 'utf-8')).toBe('test content');
    });

    it('should copy a directory recursively', () => {
      const srcDir = path.join(tempDir, 'src');
      const destDir = path.join(tempDir, 'dest');
      
      fs.mkdirSync(path.join(srcDir, 'subdir1', 'subdir2'), { recursive: true });
      fs.writeFileSync(path.join(srcDir, 'file1.txt'), 'content1');
      fs.writeFileSync(path.join(srcDir, 'subdir1', 'file2.txt'), 'content2');
      fs.writeFileSync(path.join(srcDir, 'subdir1', 'subdir2', 'file3.txt'), 'content3');

      copyRecursiveSync(srcDir, destDir);

      expect(fs.existsSync(path.join(destDir, 'file1.txt'))).toBe(true);
      expect(fs.existsSync(path.join(destDir, 'subdir1', 'file2.txt'))).toBe(true);
      expect(fs.existsSync(path.join(destDir, 'subdir1', 'subdir2', 'file3.txt'))).toBe(true);
    });

    it('should handle nested directory structure', () => {
      const srcDir = path.join(tempDir, 'src');
      const destDir = path.join(tempDir, 'dest');
      
      fs.mkdirSync(path.join(srcDir, 'a', 'b', 'c'), { recursive: true });
      fs.writeFileSync(path.join(srcDir, 'a', 'b', 'c', 'deep.txt'), 'deep content');

      copyRecursiveSync(srcDir, destDir);

      expect(fs.existsSync(path.join(destDir, 'a', 'b', 'c', 'deep.txt'))).toBe(true);
    });

    it('should overwrite existing destination directory', () => {
      const srcDir = path.join(tempDir, 'src');
      const destDir = path.join(tempDir, 'dest');
      
      fs.mkdirSync(srcDir);
      fs.mkdirSync(destDir);
      fs.writeFileSync(path.join(srcDir, 'new.txt'), 'new content');

      copyRecursiveSync(srcDir, destDir);

      expect(fs.existsSync(path.join(destDir, 'new.txt'))).toBe(true);
    });
  });

  describe('createBackup', () => {
    it('should create a backup directory with proper structure', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'plugins'), { recursive: true });
      fs.writeFileSync(path.join(wpDir, 'index.php'), '<?php // index');
      fs.writeFileSync(path.join(wpDir, 'wp-content', 'plugins', 'hello.php'), '<?php // plugin');

      const result = createBackup(wpDir);

      expect(result.success).toBe(true);
      expect(result.filesBackedUp).toBeGreaterThan(0);
      expect(result.backupPath).toContain('backups');
      expect(result.backupPath).toContain('wp-core-');
      expect(fs.existsSync(result.backupPath)).toBe(true);
    });

    it('should backup wp-content directory', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'uploads'), { recursive: true });
      fs.writeFileSync(path.join(wpDir, 'index.php'), 'index content');
      fs.writeFileSync(path.join(wpDir, 'wp-content', 'uploads', 'image.jpg'), 'image data');

      const result = createBackup(wpDir);

      expect(fs.existsSync(path.join(result.backupPath, 'wp-content'))).toBe(true);
      expect(fs.existsSync(path.join(result.backupPath, 'wp-content', 'uploads', 'image.jpg'))).toBe(true);
    });

    it('should backup wp-content with nested directories', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'themes', 'mytheme'), { recursive: true });
      fs.writeFileSync(path.join(wpDir, 'index.php'), 'index');
      fs.writeFileSync(path.join(wpDir, 'wp-content', 'themes', 'mytheme', 'style.css'), 'body {}');

      const result = createBackup(wpDir);

      expect(fs.existsSync(path.join(result.backupPath, 'wp-content', 'themes', 'mytheme', 'style.css'))).toBe(true);
    });

    it('should copy regular files to backup', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(wpDir);
      fs.writeFileSync(path.join(wpDir, 'index.php'), '<?php // index');
      fs.writeFileSync(path.join(wpDir, 'readme.html'), 'readme content');

      const result = createBackup(wpDir);

      expect(fs.existsSync(path.join(result.backupPath, 'index.php'))).toBe(true);
      expect(fs.existsSync(path.join(result.backupPath, 'readme.html'))).toBe(true);
    });

    it('should throw error for non-existent target path', () => {
      const nonExistentPath = path.join(tempDir, 'nonexistent');
      
      expect(() => createBackup(nonExistentPath)).toThrow();
    });
  });

  describe('createPluginBackup', () => {
    it('should return proper PluginBackupResult structure', () => {
      const pluginsPath = path.join(tempDir, 'plugins');
      const pluginSlug = 'test-plugin';
      fs.mkdirSync(path.join(pluginsPath, pluginSlug), { recursive: true });
      fs.writeFileSync(path.join(pluginsPath, pluginSlug, 'index.php'), '<?php // plugin');

      const result = createPluginBackup(pluginsPath, pluginSlug);

      expect(result).not.toBeNull();
      expect(result?.success).toBe(true);
      expect(result?.pluginSlug).toBe(pluginSlug);
      expect(result?.filesBackedUp).toBe(1);
      expect(result?.backupPath).toContain('backups');
      expect(result?.backupPath).toContain(`plugin-${pluginSlug}`);
    });

    it('should return null for non-existent plugin', () => {
      const pluginsPath = path.join(tempDir, 'plugins');
      fs.mkdirSync(pluginsPath);

      const result = createPluginBackup(pluginsPath, 'nonexistent-plugin');

      expect(result).toBeNull();
    });

    it('should create backup directory with plugin subdirectory', () => {
      const pluginsPath = path.join(tempDir, 'plugins');
      const pluginSlug = 'my-plugin';
      fs.mkdirSync(path.join(pluginsPath, pluginSlug), { recursive: true });
      fs.writeFileSync(path.join(pluginsPath, pluginSlug, 'main.php'), '<?php // main');
      fs.writeFileSync(path.join(pluginsPath, pluginSlug, 'readme.txt'), 'readme');

      const result = createPluginBackup(pluginsPath, pluginSlug);

      expect(fs.existsSync(path.join(result!.backupPath, pluginSlug))).toBe(true);
      expect(fs.existsSync(path.join(result!.backupPath, pluginSlug, 'main.php'))).toBe(true);
      expect(fs.existsSync(path.join(result!.backupPath, pluginSlug, 'readme.txt'))).toBe(true);
    });

    it('should handle nested plugin directory structure', () => {
      const pluginsPath = path.join(tempDir, 'plugins');
      const pluginSlug = 'complex-plugin';
      const pluginDir = path.join(pluginsPath, pluginSlug, 'includes', 'admin');
      fs.mkdirSync(pluginDir, { recursive: true });
      fs.writeFileSync(path.join(pluginsPath, pluginSlug, 'index.php'), '<?php');
      fs.writeFileSync(path.join(pluginsPath, pluginSlug, 'includes', 'helper.php'), '<?php');
      fs.writeFileSync(path.join(pluginDir, 'settings.php'), '<?php');

      const result = createPluginBackup(pluginsPath, pluginSlug);

      expect(result).not.toBeNull();
      expect(fs.existsSync(path.join(result!.backupPath, pluginSlug, 'includes', 'helper.php'))).toBe(true);
      expect(fs.existsSync(path.join(result!.backupPath, pluginSlug, 'includes', 'admin', 'settings.php'))).toBe(true);
    });

    it('should return null when plugins directory does not exist', () => {
      const pluginsPath = path.join(tempDir, 'nonexistent-plugins');

      const result = createPluginBackup(pluginsPath, 'any-plugin');

      expect(result).toBeNull();
    });
  });

  describe('BackupResult structure', () => {
    it('should return correct structure from createBackup', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(path.join(wpDir, 'wp-content'), { recursive: true });
      fs.writeFileSync(path.join(wpDir, 'index.php'), 'index content');

      const result = createBackup(wpDir);

      expect(result).toHaveProperty('success');
      expect(result).toHaveProperty('backupPath');
      expect(result).toHaveProperty('filesBackedUp');
      expect(typeof result.success).toBe('boolean');
      expect(typeof result.backupPath).toBe('string');
      expect(typeof result.filesBackedUp).toBe('number');
    });

    it('should return correct structure from createPluginBackup', () => {
      const pluginsPath = path.join(tempDir, 'plugins');
      const pluginSlug = 'test-plugin';
      fs.mkdirSync(path.join(pluginsPath, pluginSlug), { recursive: true });

      const result = createPluginBackup(pluginsPath, pluginSlug);

      expect(result).not.toBeNull();
      expect(result).toHaveProperty('success');
      expect(result).toHaveProperty('backupPath');
      expect(result).toHaveProperty('pluginSlug');
      expect(result).toHaveProperty('filesBackedUp');
    });
  });
});
