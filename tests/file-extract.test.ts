import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { copyDirRecursive, getAllFiles } from '../src/commands/file-extract';

describe('file-extract Module', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'file-extract-test-'));
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('copyDirRecursive', () => {
    it('should copy a single file', () => {
      const srcDir = path.join(tempDir, 'src');
      const destDir = path.join(tempDir, 'dest');
      fs.mkdirSync(srcDir);
      fs.writeFileSync(path.join(srcDir, 'file.txt'), 'test content');

      copyDirRecursive(srcDir, destDir);

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

      copyDirRecursive(srcDir, destDir);

      expect(fs.existsSync(path.join(destDir, 'file1.txt'))).toBe(true);
      expect(fs.existsSync(path.join(destDir, 'subdir1', 'file2.txt'))).toBe(true);
      expect(fs.existsSync(path.join(destDir, 'subdir1', 'subdir2', 'file3.txt'))).toBe(true);
    });

    it('should handle deeply nested directory structure', () => {
      const srcDir = path.join(tempDir, 'src');
      const destDir = path.join(tempDir, 'dest');
      
      fs.mkdirSync(path.join(srcDir, 'a', 'b', 'c', 'd'), { recursive: true });
      fs.writeFileSync(path.join(srcDir, 'a', 'b', 'c', 'd', 'deep.txt'), 'deep content');

      copyDirRecursive(srcDir, destDir);

      expect(fs.existsSync(path.join(destDir, 'a', 'b', 'c', 'd', 'deep.txt'))).toBe(true);
      expect(fs.readFileSync(path.join(destDir, 'a', 'b', 'c', 'd', 'deep.txt'), 'utf-8')).toBe('deep content');
    });

    it('should create destination directory if it does not exist', () => {
      const srcDir = path.join(tempDir, 'src');
      const destDir = path.join(tempDir, 'dest', 'nested');
      
      fs.mkdirSync(srcDir);
      fs.writeFileSync(path.join(srcDir, 'file.txt'), 'content');

      copyDirRecursive(srcDir, destDir);

      expect(fs.existsSync(path.join(destDir, 'file.txt'))).toBe(true);
    });

    it('should preserve file content exactly', () => {
      const srcDir = path.join(tempDir, 'src');
      const destDir = path.join(tempDir, 'dest');
      const content = 'Binary\x00Data\xff\n\r\t';
      
      fs.mkdirSync(srcDir);
      fs.writeFileSync(path.join(srcDir, 'binary.dat'), content);

      copyDirRecursive(srcDir, destDir);

      expect(fs.readFileSync(path.join(destDir, 'binary.dat'))).toEqual(Buffer.from(content));
    });
  });

  describe('getAllFiles', () => {
    it('should get all files in a nested directory', () => {
      const testDir = path.join(tempDir, 'test');
      
      fs.mkdirSync(path.join(testDir, 'dir1', 'subdir1'), { recursive: true });
      fs.mkdirSync(path.join(testDir, 'dir2'), { recursive: true });
      fs.writeFileSync(path.join(testDir, 'file1.txt'), 'content1');
      fs.writeFileSync(path.join(testDir, 'dir1', 'file2.txt'), 'content2');
      fs.writeFileSync(path.join(testDir, 'dir1', 'subdir1', 'file3.txt'), 'content3');
      fs.writeFileSync(path.join(testDir, 'dir2', 'file4.txt'), 'content4');

      const files = getAllFiles(testDir);

      expect(files.length).toBe(4);
      expect(files).toContain(path.join(testDir, 'file1.txt'));
      expect(files).toContain(path.join(testDir, 'dir1', 'file2.txt'));
      expect(files).toContain(path.join(testDir, 'dir1', 'subdir1', 'file3.txt'));
      expect(files).toContain(path.join(testDir, 'dir2', 'file4.txt'));
    });

    it('should return empty array for empty directory', () => {
      const emptyDir = path.join(tempDir, 'empty');
      fs.mkdirSync(emptyDir);

      const files = getAllFiles(emptyDir);

      expect(files).toEqual([]);
    });

    it('should return only files, not directories', () => {
      const testDir = path.join(tempDir, 'test');
      
      fs.mkdirSync(path.join(testDir, 'emptydir'), { recursive: true });
      fs.writeFileSync(path.join(testDir, 'file.txt'), 'content');

      const files = getAllFiles(testDir);

      expect(files.length).toBe(1);
      expect(files[0]).toBe(path.join(testDir, 'file.txt'));
    });

    it('should handle deeply nested directory structure', () => {
      const testDir = path.join(tempDir, 'test');
      
      fs.mkdirSync(path.join(testDir, 'a', 'b', 'c', 'd', 'e'), { recursive: true });
      fs.writeFileSync(path.join(testDir, 'root.txt'), 'root');
      fs.writeFileSync(path.join(testDir, 'a', 'level1.txt'), 'level1');
      fs.writeFileSync(path.join(testDir, 'a', 'b', 'level2.txt'), 'level2');
      fs.writeFileSync(path.join(testDir, 'a', 'b', 'c', 'level3.txt'), 'level3');
      fs.writeFileSync(path.join(testDir, 'a', 'b', 'c', 'd', 'level4.txt'), 'level4');
      fs.writeFileSync(path.join(testDir, 'a', 'b', 'c', 'd', 'e', 'level5.txt'), 'level5');

      const files = getAllFiles(testDir);

      expect(files.length).toBe(6);
    });

    it('should return files in correct order (directory entries are processed first)', () => {
      const testDir = path.join(tempDir, 'test');
      
      fs.mkdirSync(path.join(testDir, 'dir1'), { recursive: true });
      fs.writeFileSync(path.join(testDir, 'file0.txt'), '0');
      fs.writeFileSync(path.join(testDir, 'dir1', 'file1.txt'), '1');

      const files = getAllFiles(testDir);

      expect(files).toContain(path.join(testDir, 'file0.txt'));
      expect(files).toContain(path.join(testDir, 'dir1', 'file1.txt'));
      expect(files.length).toBe(2);
    });
  });
});