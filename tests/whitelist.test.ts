import { describe, it, expect, beforeEach } from '@jest/globals';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import {
  loadWhitelist,
  isPathWhitelisted,
  isSignatureWhitelisted,
  isExtensionWhitelisted,
  filterWhitelistedThreats,
  applyWhitelist,
  WhitelistConfig,
} from '../src/whitelist';
import { Threat } from '../src/malware-scanner';

let detectThreats: (filePath: string, content: string, verbose: boolean) => Threat[];

beforeEach(() => {
  jest.resetModules();
  const mod = require('../src/malware-scanner');
  detectThreats = mod.detectThreats;
});

const baseConfig: WhitelistConfig = {
  version: '1.0.0',
  description: '',
  lastUpdated: '',
  paths: [],
  signatures: [],
  extensions: [],
};

describe('Whitelist', () => {
  describe('loadWhitelist', () => {
    it('should load the default whitelist file', () => {
      const config = loadWhitelist();
      expect(config).toHaveProperty('version');
      expect(config).toHaveProperty('paths');
      expect(config).toHaveProperty('signatures');
      expect(config).toHaveProperty('extensions');
      expect(Array.isArray(config.paths)).toBe(true);
      expect(Array.isArray(config.signatures)).toBe(true);
      expect(Array.isArray(config.extensions)).toBe(true);
    });

    it('should return empty whitelist when file does not exist', () => {
      const config = loadWhitelist('/nonexistent/path/whitelist.json');
      expect(config.paths).toEqual([]);
      expect(config.signatures).toEqual([]);
      expect(config.extensions).toEqual([]);
    });

    it('should load a custom whitelist file', () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wl-test-'));
      const tmpFile = path.join(tmpDir, 'custom-whitelist.json');
      fs.writeFileSync(tmpFile, JSON.stringify({
        version: '2.0.0',
        paths: ['/safe/file.php'],
        signatures: ['php_eval'],
        extensions: ['.log'],
      }));

      const config = loadWhitelist(tmpFile);
      expect(config.version).toBe('2.0.0');
      expect(config.paths).toEqual(['/safe/file.php']);
      expect(config.signatures).toEqual(['php_eval']);
      expect(config.extensions).toEqual(['.log']);

      fs.unlinkSync(tmpFile);
      fs.rmdirSync(tmpDir);
    });

    it('should normalize extension casing', () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wl-test-'));
      const tmpFile = path.join(tmpDir, 'case-whitelist.json');
      fs.writeFileSync(tmpFile, JSON.stringify({
        extensions: ['.LOG', '.Md', '.TXT'],
      }));

      const config = loadWhitelist(tmpFile);
      expect(config.extensions).toEqual(['.log', '.md', '.txt']);

      fs.unlinkSync(tmpFile);
      fs.rmdirSync(tmpDir);
    });

    it('should handle missing arrays gracefully', () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wl-test-'));
      const tmpFile = path.join(tmpDir, 'partial-whitelist.json');
      fs.writeFileSync(tmpFile, JSON.stringify({
        version: '1.0.0',
      }));

      const config = loadWhitelist(tmpFile);
      expect(config.paths).toEqual([]);
      expect(config.signatures).toEqual([]);
      expect(config.extensions).toEqual([]);

      fs.unlinkSync(tmpFile);
      fs.rmdirSync(tmpDir);
    });
  });

  describe('isPathWhitelisted', () => {
    it('should match exact file path', () => {
      const result = isPathWhitelisted('/var/www/file.php', ['/var/www/file.php']);
      expect(result).toBe(true);
    });

    it('should match file inside whitelisted directory', () => {
      const result = isPathWhitelisted(
        '/var/www/safe/nested/file.php',
        ['/var/www/safe']
      );
      expect(result).toBe(true);
    });

    it('should not match unrelated paths', () => {
      const result = isPathWhitelisted('/var/www/other/file.php', ['/var/www/safe']);
      expect(result).toBe(false);
    });

    it('should not match partial directory names', () => {
      const result = isPathWhitelisted('/var/www/safe-backup/file.php', ['/var/www/safe']);
      expect(result).toBe(false);
    });

    it('should handle empty whitelist', () => {
      const result = isPathWhitelisted('/any/file.php', []);
      expect(result).toBe(false);
    });
  });

  describe('isSignatureWhitelisted', () => {
    it('should match whitelisted signature type', () => {
      const result = isSignatureWhitelisted('php_eval', ['php_eval', 'php_base64_decode']);
      expect(result).toBe(true);
    });

    it('should not match non-whitelisted signature', () => {
      const result = isSignatureWhitelisted('php_exec', ['php_eval', 'php_base64_decode']);
      expect(result).toBe(false);
    });

    it('should handle empty signature list', () => {
      const result = isSignatureWhitelisted('php_eval', []);
      expect(result).toBe(false);
    });
  });

  describe('isExtensionWhitelisted', () => {
    it('should match whitelisted extension', () => {
      const result = isExtensionWhitelisted('/test/file.log', ['.log', '.md']);
      expect(result).toBe(true);
    });

    it('should match case-insensitively', () => {
      const result = isExtensionWhitelisted('/test/file.LOG', ['.log']);
      expect(result).toBe(true);
    });

    it('should not match non-whitelisted extension', () => {
      const result = isExtensionWhitelisted('/test/file.php', ['.log', '.md']);
      expect(result).toBe(false);
    });

    it('should handle empty extension list', () => {
      const result = isExtensionWhitelisted('/test/file.php', []);
      expect(result).toBe(false);
    });
  });

  describe('filterWhitelistedThreats', () => {
    it('should return all threats when no whitelist entries match', () => {
      const threats: Threat[] = [
        { file: '/test/file.php', type: 'php_eval', line: 1, signature: 'eval(' },
        { file: '/test/file.php', type: 'php_base64_decode', line: 2, signature: 'base64_decode(' },
      ];

      const result = filterWhitelistedThreats(threats, '/test/file.php', baseConfig);
      expect(result).toHaveLength(2);
    });

    it('should filter threats by whitelisted signature', () => {
      const threats: Threat[] = [
        { file: '/test/file.php', type: 'php_eval', line: 1, signature: 'eval(' },
        { file: '/test/file.php', type: 'php_base64_decode', line: 2, signature: 'base64_decode(' },
      ];

      const config = { ...baseConfig, signatures: ['php_eval'] };
      const result = filterWhitelistedThreats(threats, '/test/file.php', config);
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('php_base64_decode');
    });

    it('should filter all threats when file path is whitelisted', () => {
      const threats: Threat[] = [
        { file: '/safe/file.php', type: 'php_eval', line: 1, signature: 'eval(' },
        { file: '/safe/file.php', type: 'php_base64_decode', line: 2, signature: 'base64_decode(' },
      ];

      const config = { ...baseConfig, paths: ['/safe/file.php'] };
      const result = filterWhitelistedThreats(threats, '/safe/file.php', config);
      expect(result).toHaveLength(0);
    });

    it('should filter all threats when file extension is whitelisted', () => {
      const threats: Threat[] = [
        { file: '/test/file.log', type: 'base64_large', line: null, signature: 'aaaa...' },
      ];

      const config = { ...baseConfig, extensions: ['.log'] };
      const result = filterWhitelistedThreats(threats, '/test/file.log', config);
      expect(result).toHaveLength(0);
    });
  });

  describe('applyWhitelist', () => {
    it('should filter threats across multiple files', () => {
      const threats: Threat[] = [
        { file: '/test/file1.php', type: 'php_eval', line: 1, signature: 'eval(' },
        { file: '/test/file2.php', type: 'php_base64_decode', line: 1, signature: 'base64_decode(' },
        { file: '/test/file1.php', type: 'php_exec', line: 2, signature: 'exec(' },
      ];

      const config = { ...baseConfig, signatures: ['php_eval'] };
      const result = applyWhitelist(threats, config);
      expect(result).toHaveLength(2);
      expect(result.some(t => t.type === 'php_eval')).toBe(false);
    });

    it('should filter threats from whitelisted path', () => {
      const threats: Threat[] = [
        { file: '/safe/dir/file.php', type: 'php_eval', line: 1, signature: 'eval(' },
        { file: '/other/file.php', type: 'php_eval', line: 1, signature: 'eval(' },
      ];

      const config = { ...baseConfig, paths: ['/safe/dir'] };
      const result = applyWhitelist(threats, config);
      expect(result).toHaveLength(1);
      expect(result[0].file).toBe('/other/file.php');
    });

    it('should return empty array when all threats are whitelisted', () => {
      const threats: Threat[] = [
        { file: '/test/file.log', type: 'base64_large', line: null, signature: 'aaaa...' },
      ];

      const config = { ...baseConfig, extensions: ['.log'] };
      const result = applyWhitelist(threats, config);
      expect(result).toHaveLength(0);
    });

    it('should return empty array for empty threats', () => {
      const result = applyWhitelist([], baseConfig);
      expect(result).toHaveLength(0);
    });
  });

  describe('Default whitelist.json', () => {
    it('should exist in signatures directory', () => {
      const config = loadWhitelist();
      expect(config.version).toBeTruthy();
    });

    it('should whitelist .log, .md, .txt by default', () => {
      const config = loadWhitelist();
      expect(config.extensions).toContain('.log');
      expect(config.extensions).toContain('.md');
      expect(config.extensions).toContain('.txt');
    });
  });
});
