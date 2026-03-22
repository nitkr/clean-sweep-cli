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

    it('should copy empty source directory', () => {
      const srcDir = path.join(tempDir, 'src');
      const destDir = path.join(tempDir, 'dest');
      fs.mkdirSync(srcDir);

      copyDirRecursive(srcDir, destDir);

      expect(fs.existsSync(destDir)).toBe(true);
      expect(fs.readdirSync(destDir).length).toBe(0);
    });

    it('should handle files with special characters in names', () => {
      const srcDir = path.join(tempDir, 'src');
      const destDir = path.join(tempDir, 'dest');
      
      fs.mkdirSync(srcDir);
      const specialFiles = [
        'file with spaces.txt',
        'file-with-dashes.txt',
        'file_with_underscores.txt',
        'file.with.dots.txt',
        'file-with-multiple...dots.txt',
        '123file-starting-with-numbers.txt',
        'UPPERCASE.TXT',
        'MixedCase.File.txt',
        'file-with-dash-and-spaces test.txt',
      ];
      
      specialFiles.forEach(fileName => {
        fs.writeFileSync(path.join(srcDir, fileName), `content of ${fileName}`);
      });

      copyDirRecursive(srcDir, destDir);

      specialFiles.forEach(fileName => {
        expect(fs.existsSync(path.join(destDir, fileName))).toBe(true);
        expect(fs.readFileSync(path.join(destDir, fileName), 'utf-8')).toBe(`content of ${fileName}`);
      });
    });

    it('should overwrite existing files', () => {
      const srcDir = path.join(tempDir, 'src');
      const destDir = path.join(tempDir, 'dest');
      
      fs.mkdirSync(srcDir);
      fs.mkdirSync(destDir);
      fs.writeFileSync(path.join(srcDir, 'file.txt'), 'new content');
      fs.writeFileSync(path.join(destDir, 'file.txt'), 'old content');

      copyDirRecursive(srcDir, destDir);

      expect(fs.readFileSync(path.join(destDir, 'file.txt'), 'utf-8')).toBe('new content');
    });

    it('should copy nested empty directories', () => {
      const srcDir = path.join(tempDir, 'src');
      const destDir = path.join(tempDir, 'dest');
      
      fs.mkdirSync(path.join(srcDir, 'level1', 'level2', 'level3'), { recursive: true });

      copyDirRecursive(srcDir, destDir);

      expect(fs.existsSync(path.join(destDir, 'level1', 'level2', 'level3'))).toBe(true);
      expect(fs.statSync(path.join(destDir, 'level1', 'level2', 'level3')).isDirectory()).toBe(true);
    });

    it('should handle mixed empty and non-empty nested directories', () => {
      const srcDir = path.join(tempDir, 'src');
      const destDir = path.join(tempDir, 'dest');
      
      fs.mkdirSync(path.join(srcDir, 'emptyDir'), { recursive: true });
      fs.mkdirSync(path.join(srcDir, 'nonEmpty', 'nested'), { recursive: true });
      fs.writeFileSync(path.join(srcDir, 'root.txt'), 'root content');
      fs.writeFileSync(path.join(srcDir, 'nonEmpty', 'file.txt'), 'nested file');
      fs.writeFileSync(path.join(srcDir, 'nonEmpty', 'nested', 'deep.txt'), 'deep content');

      copyDirRecursive(srcDir, destDir);

      expect(fs.existsSync(path.join(destDir, 'emptyDir'))).toBe(true);
      expect(fs.existsSync(path.join(destDir, 'root.txt'))).toBe(true);
      expect(fs.existsSync(path.join(destDir, 'nonEmpty', 'file.txt'))).toBe(true);
      expect(fs.existsSync(path.join(destDir, 'nonEmpty', 'nested', 'deep.txt'))).toBe(true);
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

    it('should return empty array for directory with only subdirectories', () => {
      const testDir = path.join(tempDir, 'test');
      
      fs.mkdirSync(path.join(testDir, 'dir1'), { recursive: true });
      fs.mkdirSync(path.join(testDir, 'dir2', 'nested'), { recursive: true });

      const files = getAllFiles(testDir);

      expect(files).toEqual([]);
    });

    it('should handle deeply nested empty directories', () => {
      const testDir = path.join(tempDir, 'test');
      
      fs.mkdirSync(path.join(testDir, 'a', 'b', 'c', 'd', 'e', 'f', 'g'), { recursive: true });

      const files = getAllFiles(testDir);

      expect(files).toEqual([]);
    });

    it('should handle files with special characters in names', () => {
      const testDir = path.join(tempDir, 'test');
      
      fs.mkdirSync(testDir);
      const specialFiles = [
        'file with spaces.txt',
        'file-with-dashes.txt',
        'file_with_underscores.txt',
        'file.with.dots.txt',
        'file-with-multiple...dots.txt',
        '123file-starting-with-numbers.txt',
        'UPPERCASE.TXT',
        'MixedCase.File.txt',
        'file-with-dash-and-spaces test.txt',
        'very-long-file-name-that-exceeds-typical-limits-and-tests-how-the-system-handles-extremely-long-path-components-with-multiple-dots-and-spaces-and-special-characters.txt',
      ];
      
      specialFiles.forEach(fileName => {
        fs.writeFileSync(path.join(testDir, fileName), `content of ${fileName}`);
      });

      const files = getAllFiles(testDir);

      expect(files.length).toBe(specialFiles.length);
      specialFiles.forEach(fileName => {
        expect(files).toContain(path.join(testDir, fileName));
      });
    });

    it('should handle large number of files', () => {
      const testDir = path.join(tempDir, 'test');
      
      fs.mkdirSync(testDir);
      const fileCount = 500;
      
      for (let i = 0; i < fileCount; i++) {
        fs.writeFileSync(path.join(testDir, `file-${i}.txt`), `content ${i}`);
      }

      const files = getAllFiles(testDir);

      expect(files.length).toBe(fileCount);
    });

    it('should handle large number of files in nested directories', () => {
      const testDir = path.join(tempDir, 'test');
      
      const dirs = ['dir1', 'dir2', 'dir3'];
      const filesPerDir = 100;
      
      dirs.forEach(dir => {
        fs.mkdirSync(path.join(testDir, dir), { recursive: true });
        for (let i = 0; i < filesPerDir; i++) {
          fs.writeFileSync(path.join(testDir, dir, `file-${i}.txt`), `content ${i}`);
        }
      });

      const files = getAllFiles(testDir);

      expect(files.length).toBe(dirs.length * filesPerDir);
    });

    it('should handle files with similar names in different directories', () => {
      const testDir = path.join(tempDir, 'test');
      
      fs.mkdirSync(path.join(testDir, 'dir1'), { recursive: true });
      fs.mkdirSync(path.join(testDir, 'dir2'), { recursive: true });
      fs.writeFileSync(path.join(testDir, 'same-name.txt'), 'root');
      fs.writeFileSync(path.join(testDir, 'dir1', 'same-name.txt'), 'dir1');
      fs.writeFileSync(path.join(testDir, 'dir2', 'same-name.txt'), 'dir2');

      const files = getAllFiles(testDir);

      expect(files.length).toBe(3);
      expect(files).toContain(path.join(testDir, 'same-name.txt'));
      expect(files).toContain(path.join(testDir, 'dir1', 'same-name.txt'));
      expect(files).toContain(path.join(testDir, 'dir2', 'same-name.txt'));
    });
  });
});