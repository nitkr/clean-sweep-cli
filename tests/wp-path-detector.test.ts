import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { detectWordPressRoot, findWordPressRoot, resolveWordPressPath, formatWpPathError } from '../src/wp-path-detector';

function createTempWpStructure(): { root: string; cleanup: () => void } {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wp-detect-test-'));
  const wpRoot = path.join(tmpDir, 'sites', 'mywp');
  const nested = path.join(wpRoot, 'wp-content', 'themes', 'mytheme');

  fs.mkdirSync(nested, { recursive: true });
  fs.writeFileSync(path.join(wpRoot, 'wp-config.php'), '<?php /* test */');
  fs.writeFileSync(path.join(nested, 'style.css'), '/* test */');

  return {
    root: wpRoot,
    cleanup: () => fs.rmSync(tmpDir, { recursive: true, force: true }),
  };
}

describe('findWordPressRoot', () => {
  test('finds wp-config.php in the start directory', () => {
    const { root, cleanup } = createTempWpStructure();
    try {
      const result = findWordPressRoot(root);
      expect(result).toBe(root);
    } finally {
      cleanup();
    }
  });

  test('walks up parent directories to find wp-config.php', () => {
    const { root, cleanup } = createTempWpStructure();
    try {
      const nested = path.join(root, 'wp-content', 'themes', 'mytheme');
      const result = findWordPressRoot(nested);
      expect(result).toBe(root);
    } finally {
      cleanup();
    }
  });

  test('returns null when no wp-config.php is found', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wp-nope-'));
    try {
      const result = findWordPressRoot(tmpDir);
      expect(result).toBeNull();
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});

describe('detectWordPressRoot', () => {
  test('returns found=true when wp-config.php is found', () => {
    const { root, cleanup } = createTempWpStructure();
    try {
      const result = detectWordPressRoot(root);
      expect(result.found).toBe(true);
      expect(result.path).toBe(root);
      expect(result.searchedPaths).toContain(root);
    } finally {
      cleanup();
    }
  });

  test('returns found=true walking up from nested directory', () => {
    const { root, cleanup } = createTempWpStructure();
    try {
      const nested = path.join(root, 'wp-content', 'themes', 'mytheme');
      const result = detectWordPressRoot(nested);
      expect(result.found).toBe(true);
      expect(result.path).toBe(root);
      expect(result.searchedPaths).toContain(nested);
      expect(result.searchedPaths).toContain(root);
    } finally {
      cleanup();
    }
  });

  test('returns found=false with all searched paths when not found', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wp-notfound-'));
    const sub = path.join(tmpDir, 'a', 'b');
    fs.mkdirSync(sub, { recursive: true });
    try {
      const result = detectWordPressRoot(sub);
      expect(result.found).toBe(false);
      expect(result.path).toBe(sub);
      expect(result.searchedPaths.length).toBeGreaterThanOrEqual(3);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('uses process.cwd() when no startPath is provided', () => {
    const result = detectWordPressRoot();
    expect(result).toHaveProperty('found');
    expect(result).toHaveProperty('path');
    expect(result).toHaveProperty('searchedPaths');
  });
});

describe('resolveWordPressPath', () => {
  test('returns the same path if wp-config.php exists there', () => {
    const { root, cleanup } = createTempWpStructure();
    try {
      const result = resolveWordPressPath(root);
      expect(result.found).toBe(true);
      expect(result.path).toBe(root);
      expect(result.searchedPaths).toEqual([root]);
    } finally {
      cleanup();
    }
  });

  test('walks up if wp-config.php is not in target path', () => {
    const { root, cleanup } = createTempWpStructure();
    try {
      const nested = path.join(root, 'wp-content');
      const result = resolveWordPressPath(nested);
      expect(result.found).toBe(true);
      expect(result.path).toBe(root);
    } finally {
      cleanup();
    }
  });
});

describe('formatWpPathError', () => {
  test('formats error message with searched paths and command name', () => {
    const result = formatWpPathError(
      { path: '/foo', found: false, searchedPaths: ['/foo', '/'] },
      'scan'
    );
    expect(result).toContain('WordPress installation not found');
    expect(result).toContain('/foo');
    expect(result).toContain('clean-sweep scan --path /path/to/wordpress');
  });
});
