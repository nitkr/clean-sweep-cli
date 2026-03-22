import { describe, it, expect } from '@jest/globals';
import * as path from 'path';
import * as fs from 'fs';
import { parseWpConfig, parseMysqlOutput } from '../src/commands/db-scan';

describe('db-scan', () => {
  describe('parseWpConfig', () => {
    const tempDir = fs.mkdtempSync('wp-config-test-');

    afterAll(() => {
      fs.rmSync(tempDir, { recursive: true, force: true });
    });

    it('should parse valid wp-config.php content', () => {
      const wpConfigContent = `<?php
define('DB_NAME', 'wordpress_db');
define('DB_USER', 'wp_user');
define('DB_PASSWORD', 'wp_pass');
define('DB_HOST', 'localhost');
$table_prefix = 'wp_';
`;

      const configPath = path.join(tempDir, 'wp-config.php');
      fs.writeFileSync(configPath, wpConfigContent);

      const result = parseWpConfig(configPath);

      expect(result).not.toBeNull();
      expect(result?.name).toBe('wordpress_db');
      expect(result?.user).toBe('wp_user');
      expect(result?.pass).toBe('wp_pass');
      expect(result?.host).toBe('localhost');
      expect(result?.prefix).toBe('wp_');
    });

    it('should return null for non-existent file', () => {
      const result = parseWpConfig('/nonexistent/path/wp-config.php');
      expect(result).toBeNull();
    });

    it('should return null when DB_NAME is missing', () => {
      const wpConfigContent = `<?php
define('DB_USER', 'wp_user');
define('DB_PASSWORD', 'wp_pass');
define('DB_HOST', 'localhost');
$table_prefix = 'wp_';
`;

      const configPath = path.join(tempDir, 'wp-config-missing-name.php');
      fs.writeFileSync(configPath, wpConfigContent);

      const result = parseWpConfig(configPath);
      expect(result).toBeNull();
    });

    it('should return null when DB_USER is missing', () => {
      const wpConfigContent = `<?php
define('DB_NAME', 'wordpress_db');
define('DB_PASSWORD', 'wp_pass');
define('DB_HOST', 'localhost');
$table_prefix = 'wp_';
`;

      const configPath = path.join(tempDir, 'wp-config-missing-user.php');
      fs.writeFileSync(configPath, wpConfigContent);

      const result = parseWpConfig(configPath);
      expect(result).toBeNull();
    });

    it('should use default host when DB_HOST is missing', () => {
      const wpConfigContent = `<?php
define('DB_NAME', 'wordpress_db');
define('DB_USER', 'wp_user');
define('DB_PASSWORD', 'wp_pass');
$table_prefix = 'wp_';
`;

      const configPath = path.join(tempDir, 'wp-config-no-host.php');
      fs.writeFileSync(configPath, wpConfigContent);

      const result = parseWpConfig(configPath);

      expect(result).not.toBeNull();
      expect(result?.host).toBe('localhost');
    });

    it('should use default prefix when table_prefix is missing', () => {
      const wpConfigContent = `<?php
define('DB_NAME', 'wordpress_db');
define('DB_USER', 'wp_user');
define('DB_PASSWORD', 'wp_pass');
define('DB_HOST', 'localhost');
`;

      const configPath = path.join(tempDir, 'wp-config-no-prefix.php');
      fs.writeFileSync(configPath, wpConfigContent);

      const result = parseWpConfig(configPath);

      expect(result).not.toBeNull();
      expect(result?.prefix).toBe('wp_');
    });

    it('should handle empty password', () => {
      const wpConfigContent = `<?php
define('DB_NAME', 'wordpress_db');
define('DB_USER', 'wp_user');
define('DB_PASSWORD', '');
define('DB_HOST', 'localhost');
$table_prefix = 'wp_';
`;

      const configPath = path.join(tempDir, 'wp-config-empty-pass.php');
      fs.writeFileSync(configPath, wpConfigContent);

      const result = parseWpConfig(configPath);

      expect(result).not.toBeNull();
      expect(result?.pass).toBe('');
    });
  });

  describe('parseMysqlOutput', () => {
    it('should parse valid MySQL output with headers', () => {
      const output = 'ID\tpost_content\n1\tSome content here\n2\tMore content';
      const result = parseMysqlOutput(output);

      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({ id: 1, content: 'Some content here' });
      expect(result[1]).toEqual({ id: 2, content: 'More content' });
    });

    it('should return empty array for empty output', () => {
      const result = parseMysqlOutput('');
      expect(result).toHaveLength(0);
    });

    it('should return empty array for output with only newline', () => {
      const result = parseMysqlOutput('\n');
      expect(result).toHaveLength(0);
    });

    it('should return empty array when output has only headers', () => {
      const output = 'ID\tpost_content';
      const result = parseMysqlOutput(output);
      expect(result).toHaveLength(0);
    });

    it('should handle output without ID column', () => {
      const output = 'post_content\nSome content here\nMore content';
      const result = parseMysqlOutput(output);

      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({ id: 1, content: 'Some content here' });
      expect(result[1]).toEqual({ id: 2, content: 'More content' });
    });

    it('should handle single column output', () => {
      const output = 'option_value\nsome_value\nanother_value';
      const result = parseMysqlOutput(output);

      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({ id: 1, content: 'some_value' });
      expect(result[1]).toEqual({ id: 2, content: 'another_value' });
    });

    it('should handle output with empty content', () => {
      const output = 'ID\tpost_content\n1\t\n2\tSome content';
      const result = parseMysqlOutput(output);

      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({ id: 1, content: '' });
      expect(result[1]).toEqual({ id: 2, content: 'Some content' });
    });

    it('should handle multiple rows with varying columns', () => {
      const output = 'ID\tpost_content\tpost_title\n1\tContent One\tTitle One\n2\tContent Two\tTitle Two';
      const result = parseMysqlOutput(output);

      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({ id: 1, content: 'Content One' });
      expect(result[1]).toEqual({ id: 2, content: 'Content Two' });
    });
  });
});