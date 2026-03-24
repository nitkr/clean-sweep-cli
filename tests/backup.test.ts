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
      expect(result.backupPath).toContain(path.join('clean-sweep-cli', 'backups'));
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
      expect(result?.backupPath).toContain(path.join('clean-sweep-cli', 'backups'));
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

  describe('createBackup edge cases', () => {
    it('should handle empty wp-content directory', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(wpDir, { recursive: true });
      fs.mkdirSync(path.join(wpDir, 'wp-content'));
      fs.writeFileSync(path.join(wpDir, 'index.php'), 'index');

      const result = createBackup(wpDir);

      expect(result.success).toBe(true);
      expect(fs.existsSync(path.join(result.backupPath, 'wp-content'))).toBe(true);
    });

    it('should handle files with special characters in names', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'uploads'), { recursive: true });
      fs.writeFileSync(path.join(wpDir, 'index.php'), 'index');
      fs.writeFileSync(path.join(wpDir, 'wp-content', 'uploads', 'file with spaces.txt'), 'content');
      fs.writeFileSync(path.join(wpDir, 'wp-content', 'uploads', 'file-with-dashes.txt'), 'content');
      fs.writeFileSync(path.join(wpDir, 'wp-content', 'uploads', 'file_with_underscores.txt'), 'content');
      fs.writeFileSync(path.join(wpDir, 'wp-content', 'uploads', 'file.multiple.dots.txt'), 'content');

      const result = createBackup(wpDir);

      expect(result.success).toBe(true);
      expect(fs.existsSync(path.join(result.backupPath, 'wp-content', 'uploads', 'file with spaces.txt'))).toBe(true);
      expect(fs.existsSync(path.join(result.backupPath, 'wp-content', 'uploads', 'file-with-dashes.txt'))).toBe(true);
      expect(fs.existsSync(path.join(result.backupPath, 'wp-content', 'uploads', 'file_with_underscores.txt'))).toBe(true);
      expect(fs.existsSync(path.join(result.backupPath, 'wp-content', 'uploads', 'file.multiple.dots.txt'))).toBe(true);
    });

    it('should handle deeply nested directory structures', () => {
      const wpDir = path.join(tempDir, 'wp');
      const nestedPath = path.join(wpDir, 'wp-content', 'plugins', 'my-plugin', 'includes', 'classes', 'models', 'legacy');
      fs.mkdirSync(nestedPath, { recursive: true });
      fs.writeFileSync(path.join(wpDir, 'index.php'), 'index');
      fs.writeFileSync(path.join(nestedPath, 'handler.php'), '<?php');

      const result = createBackup(wpDir);

      expect(result.success).toBe(true);
      expect(fs.existsSync(path.join(result.backupPath, 'wp-content', 'plugins', 'my-plugin', 'includes', 'classes', 'models', 'legacy', 'handler.php'))).toBe(true);
    });

    it('should handle preserve files with special characters', () => {
      const wpDir = path.join(tempDir, 'wp-preserve');
      fs.mkdirSync(wpDir, { recursive: true });
      fs.writeFileSync(path.join(wpDir, 'index.php'), 'index');
      fs.writeFileSync(path.join(wpDir, 'wp-config.php'), 'config content');
      const htaccessPath = path.join(wpDir, '.htaccess');
      fs.writeFileSync(htaccessPath, 'rewrite rules');
      fs.writeFileSync(path.join(wpDir, 'robots.txt'), 'user-agent: *');

      const stat = fs.statSync(htaccessPath);
      expect(stat.isFile()).toBe(true);

      const result = createBackup(wpDir);

      expect(result.success).toBe(true);
      expect(fs.existsSync(path.join(result.backupPath, 'wp-config.php'))).toBe(true);
      expect(fs.existsSync(path.join(result.backupPath, '.htaccess'))).toBe(true);
      expect(fs.existsSync(path.join(result.backupPath, 'robots.txt'))).toBe(true);
    });
  });

  describe('copyRecursiveSync edge cases', () => {
    it('should handle empty source directory', () => {
      const srcDir = path.join(tempDir, 'empty-src');
      const destDir = path.join(tempDir, 'empty-dest');
      fs.mkdirSync(srcDir);

      copyRecursiveSync(srcDir, destDir);

      expect(fs.existsSync(destDir)).toBe(true);
      expect(fs.statSync(destDir).isDirectory()).toBe(true);
    });

    it('should handle files with special characters in names', () => {
      const srcDir = path.join(tempDir, 'src-special');
      const destDir = path.join(tempDir, 'dest-special');
      fs.mkdirSync(srcDir);
      fs.writeFileSync(path.join(srcDir, 'file with spaces.txt'), 'content');
      fs.writeFileSync(path.join(srcDir, 'café.txt'), 'content');
      fs.writeFileSync(path.join(srcDir, 'emoji-🎉.txt'), 'content');
      fs.writeFileSync(path.join(srcDir, 'unicode-日本語.txt'), 'content');

      copyRecursiveSync(srcDir, destDir);

      expect(fs.existsSync(path.join(destDir, 'file with spaces.txt'))).toBe(true);
      expect(fs.existsSync(path.join(destDir, 'café.txt'))).toBe(true);
      expect(fs.existsSync(path.join(destDir, 'emoji-🎉.txt'))).toBe(true);
      expect(fs.existsSync(path.join(destDir, 'unicode-日本語.txt'))).toBe(true);
    });

    it('should handle symbolic links to files', () => {
      const srcDir = path.join(tempDir, 'src-symlink');
      const destDir = path.join(tempDir, 'dest-symlink');
      const realFile = path.join(tempDir, 'real-file.txt');
      
      fs.mkdirSync(srcDir);
      fs.writeFileSync(realFile, 'real content');
      fs.symlinkSync(realFile, path.join(srcDir, 'link.txt'), 'file');

      copyRecursiveSync(srcDir, destDir);

      expect(fs.existsSync(path.join(destDir, 'link.txt'))).toBe(true);
      expect(fs.lstatSync(path.join(destDir, 'link.txt')).isSymbolicLink()).toBe(false);
      expect(fs.readFileSync(path.join(destDir, 'link.txt'), 'utf-8')).toBe('real content');
    });

    it('should handle symbolic links to directories', () => {
      const srcDir = path.join(tempDir, 'src-dir-symlink');
      const destDir = path.join(tempDir, 'dest-dir-symlink');
      const realDir = path.join(tempDir, 'real-dir');
      
      fs.mkdirSync(realDir, { recursive: true });
      fs.mkdirSync(srcDir, { recursive: true });
      fs.writeFileSync(path.join(realDir, 'file.txt'), 'content');
      fs.symlinkSync(realDir, path.join(srcDir, 'link-dir'), 'dir');

      copyRecursiveSync(srcDir, destDir);

      expect(fs.existsSync(path.join(destDir, 'link-dir'))).toBe(true);
      expect(fs.existsSync(path.join(destDir, 'link-dir', 'file.txt'))).toBe(true);
    });

    it('should handle hidden files starting with dot', () => {
      const srcDir = path.join(tempDir, 'src-hidden');
      const destDir = path.join(tempDir, 'dest-hidden');
      fs.mkdirSync(srcDir);
      fs.writeFileSync(path.join(srcDir, '.hidden'), 'hidden content');
      fs.writeFileSync(path.join(srcDir, '.env'), 'env content');
      fs.writeFileSync(path.join(srcDir, 'normal.txt'), 'normal');

      copyRecursiveSync(srcDir, destDir);

      expect(fs.existsSync(path.join(destDir, '.hidden'))).toBe(true);
      expect(fs.existsSync(path.join(destDir, '.env'))).toBe(true);
      expect(fs.existsSync(path.join(destDir, 'normal.txt'))).toBe(true);
    });

    it('should handle multiple files at root level', () => {
      const srcDir = path.join(tempDir, 'src-many');
      const destDir = path.join(tempDir, 'dest-many');
      fs.mkdirSync(srcDir);
      
      for (let i = 0; i < 50; i++) {
        fs.writeFileSync(path.join(srcDir, `file-${i}.txt`), `content ${i}`);
      }

      copyRecursiveSync(srcDir, destDir);

      for (let i = 0; i < 50; i++) {
        expect(fs.existsSync(path.join(destDir, `file-${i}.txt`))).toBe(true);
      }
    });
  });

  describe('createPluginBackup edge cases', () => {
    it('should return null when plugin directory does not exist', () => {
      const pluginsPath = path.join(tempDir, 'plugins');
      fs.mkdirSync(pluginsPath);

      const result = createPluginBackup(pluginsPath, 'definitely-nonexistent-plugin-12345');

      expect(result).toBeNull();
    });

    it('should handle plugin with multiple file types', () => {
      const pluginsPath = path.join(tempDir, 'plugins-multi');
      const pluginSlug = 'multi-type-plugin';
      const pluginDir = path.join(pluginsPath, pluginSlug);
      
      fs.mkdirSync(pluginDir, { recursive: true });
      fs.writeFileSync(path.join(pluginDir, 'index.php'), '<?php');
      fs.writeFileSync(path.join(pluginDir, 'readme.txt'), 'readme');
      fs.writeFileSync(path.join(pluginDir, 'style.css'), 'body {}');
      fs.writeFileSync(path.join(pluginDir, 'uninstall.php'), '<?php');
      fs.writeFileSync(path.join(pluginDir, 'license.txt'), 'MIT');
      fs.writeFileSync(path.join(pluginDir, 'package.json'), '{}');

      const result = createPluginBackup(pluginsPath, pluginSlug);

      expect(result).not.toBeNull();
      expect(result?.success).toBe(true);
      expect(fs.existsSync(path.join(result!.backupPath, pluginSlug, 'index.php'))).toBe(true);
      expect(fs.existsSync(path.join(result!.backupPath, pluginSlug, 'readme.txt'))).toBe(true);
      expect(fs.existsSync(path.join(result!.backupPath, pluginSlug, 'style.css'))).toBe(true);
      expect(fs.existsSync(path.join(result!.backupPath, pluginSlug, 'uninstall.php'))).toBe(true);
      expect(fs.existsSync(path.join(result!.backupPath, pluginSlug, 'license.txt'))).toBe(true);
      expect(fs.existsSync(path.join(result!.backupPath, pluginSlug, 'package.json'))).toBe(true);
    });

    it('should handle plugin with deeply nested directories', () => {
      const pluginsPath = path.join(tempDir, 'plugins');
      const pluginSlug = 'deep-plugin';
      const nestedDir = path.join(pluginsPath, pluginSlug, 'src', 'Legacy', 'Vendor', 'Custom');
      
      fs.mkdirSync(nestedDir, { recursive: true });
      fs.writeFileSync(path.join(pluginsPath, pluginSlug, 'index.php'), '<?php');
      fs.writeFileSync(path.join(pluginsPath, pluginSlug, 'src', 'loader.php'), '<?php');
      fs.writeFileSync(path.join(nestedDir, 'handler.php'), '<?php');

      const result = createPluginBackup(pluginsPath, pluginSlug);

      expect(result).not.toBeNull();
      expect(fs.existsSync(path.join(result!.backupPath, pluginSlug, 'src', 'loader.php'))).toBe(true);
      expect(fs.existsSync(path.join(result!.backupPath, pluginSlug, 'src', 'Legacy', 'Vendor', 'Custom', 'handler.php'))).toBe(true);
    });

    it('should handle plugin with empty directories', () => {
      const pluginsPath = path.join(tempDir, 'plugins');
      const pluginSlug = 'empty-dirs-plugin';
      
      fs.mkdirSync(path.join(pluginsPath, pluginSlug, 'includes'), { recursive: true });
      fs.mkdirSync(path.join(pluginsPath, pluginSlug, 'languages'), { recursive: true });
      fs.mkdirSync(path.join(pluginsPath, pluginSlug, 'templates'), { recursive: true });
      fs.writeFileSync(path.join(pluginsPath, pluginSlug, 'index.php'), '<?php');

      const result = createPluginBackup(pluginsPath, pluginSlug);

      expect(result).not.toBeNull();
      expect(fs.existsSync(path.join(result!.backupPath, pluginSlug, 'index.php'))).toBe(true);
      expect(fs.existsSync(path.join(result!.backupPath, pluginSlug, 'includes'))).toBe(true);
      expect(fs.existsSync(path.join(result!.backupPath, pluginSlug, 'languages'))).toBe(true);
      expect(fs.existsSync(path.join(result!.backupPath, pluginSlug, 'templates'))).toBe(true);
    });

    it('should handle plugin slug with special characters', () => {
      const pluginsPath = path.join(tempDir, 'plugins-special');
      const pluginSlug = 'my-awesome-plugin-v2';
      
      fs.mkdirSync(path.join(pluginsPath, pluginSlug), { recursive: true });
      fs.writeFileSync(path.join(pluginsPath, pluginSlug, 'index.php'), '<?php');

      const result = createPluginBackup(pluginsPath, pluginSlug);

      expect(result).not.toBeNull();
      expect(result?.backupPath).toContain(pluginSlug);
      expect(fs.existsSync(path.join(result!.backupPath, pluginSlug, 'index.php'))).toBe(true);
    });
  });
});
