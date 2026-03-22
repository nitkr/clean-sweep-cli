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

    it('should handle config with comments', () => {
      const wpConfigContent = `<?php
// This is a comment
define('DB_NAME', 'wordpress_db'); // database name
define('DB_USER', 'wp_user');
/* Multi-line
   comment */
define('DB_PASSWORD', 'wp_pass');
define('DB_HOST', 'localhost');
$table_prefix = 'wp_';
`;

      const configPath = path.join(tempDir, 'wp-config-comments.php');
      fs.writeFileSync(configPath, wpConfigContent);

      const result = parseWpConfig(configPath);

      expect(result).not.toBeNull();
      expect(result?.name).toBe('wordpress_db');
      expect(result?.user).toBe('wp_user');
      expect(result?.pass).toBe('wp_pass');
      expect(result?.host).toBe('localhost');
      expect(result?.prefix).toBe('wp_');
    });

    it('should handle config with different spacing and formatting', () => {
      const wpConfigContent = `<?php
define(  'DB_NAME'  ,  'wordpress_db'  );
define('DB_USER','wp_user');
define('DB_PASSWORD', 'wp_pass');
define( 'DB_HOST' , 'localhost' );
$table_prefix = 'wp_';
`;

      const configPath = path.join(tempDir, 'wp-config-spacing.php');
      fs.writeFileSync(configPath, wpConfigContent);

      const result = parseWpConfig(configPath);

      expect(result).not.toBeNull();
      expect(result?.name).toBe('wordpress_db');
      expect(result?.user).toBe('wp_user');
      expect(result?.pass).toBe('wp_pass');
      expect(result?.host).toBe('localhost');
      expect(result?.prefix).toBe('wp_');
    });

    it('should handle config with custom port in DB_HOST', () => {
      const wpConfigContent = `<?php
define('DB_NAME', 'wordpress_db');
define('DB_USER', 'wp_user');
define('DB_PASSWORD', 'wp_pass');
define('DB_HOST', 'localhost:3306');
$table_prefix = 'wp_';
`;

      const configPath = path.join(tempDir, 'wp-config-port.php');
      fs.writeFileSync(configPath, wpConfigContent);

      const result = parseWpConfig(configPath);

      expect(result).not.toBeNull();
      expect(result?.host).toBe('localhost:3306');
    });

    it('should handle config with custom table prefix', () => {
      const wpConfigContent = `<?php
define('DB_NAME', 'wordpress_db');
define('DB_USER', 'wp_user');
define('DB_PASSWORD', 'wp_pass');
define('DB_HOST', 'localhost');
$table_prefix = 'custom_prefix_';
`;

      const configPath = path.join(tempDir, 'wp-config-custom-prefix.php');
      fs.writeFileSync(configPath, wpConfigContent);

      const result = parseWpConfig(configPath);

      expect(result).not.toBeNull();
      expect(result?.prefix).toBe('custom_prefix_');
    });

    it('should handle config with numeric values in quotes', () => {
      const wpConfigContent = `<?php
define('DB_NAME', 'wordpress_db');
define('DB_USER', 'wp_user');
define('DB_PASSWORD', '12345');
define('DB_HOST', 'localhost');
$table_prefix = 'wp_';
`;

      const configPath = path.join(tempDir, 'wp-config-numeric.php');
      fs.writeFileSync(configPath, wpConfigContent);

      const result = parseWpConfig(configPath);

      expect(result).not.toBeNull();
      expect(result?.pass).toBe('12345');
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

    it('should handle multiple rows', () => {
      const output = 'ID\tpost_content\n1\tFirst row\n2\tSecond row\n3\tThird row\n4\tFourth row\n5\tFifth row';
      const result = parseMysqlOutput(output);

      expect(result).toHaveLength(5);
      expect(result[0]).toEqual({ id: 1, content: 'First row' });
      expect(result[1]).toEqual({ id: 2, content: 'Second row' });
      expect(result[2]).toEqual({ id: 3, content: 'Third row' });
      expect(result[3]).toEqual({ id: 4, content: 'Fourth row' });
      expect(result[4]).toEqual({ id: 5, content: 'Fifth row' });
    });

    it('should handle rows with special characters', () => {
      const output = 'ID\tpost_content\n1\t<script>alert(1)</script>\n2\tSome "quoted" text\n3\tText with <iframe>';
      const result = parseMysqlOutput(output);

      expect(result).toHaveLength(3);
      expect(result[0]).toEqual({ id: 1, content: '<script>alert(1)</script>' });
      expect(result[1]).toEqual({ id: 2, content: 'Some "quoted" text' });
      expect(result[2]).toEqual({ id: 3, content: 'Text with <iframe>' });
    });

    it('should handle malformed output with missing columns', () => {
      const output = 'ID\tpost_content\n1\tHas content\n2';
      const result = parseMysqlOutput(output);

      expect(result).toHaveLength(1);
      expect(result[0]).toEqual({ id: 1, content: 'Has content' });
    });

    it('should handle malformed output with extra newlines', () => {
      const output = '\n\nID\tpost_content\n\n1\tSome content\n\n2\tMore content\n\n';
      const result = parseMysqlOutput(output);

      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({ id: 1, content: 'Some content' });
      expect(result[1]).toEqual({ id: 2, content: 'More content' });
    });

    it('should handle output with mixed tab and space content', () => {
      const output = 'ID\tpost_content\n1\tText with   spaces\n2\tNormal text';
      const result = parseMysqlOutput(output);

      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({ id: 1, content: 'Text with   spaces' });
      expect(result[1]).toEqual({ id: 2, content: 'Normal text' });
    });

    it('should handle output with unicode characters', () => {
      const output = 'ID\tpost_content\n1\tHéllo wörld\n2\t日本語テスト\n3\tEmoji 😀 test';
      const result = parseMysqlOutput(output);

      expect(result).toHaveLength(3);
      expect(result[0]).toEqual({ id: 1, content: 'Héllo wörld' });
      expect(result[1]).toEqual({ id: 2, content: '日本語テスト' });
      expect(result[2]).toEqual({ id: 3, content: 'Emoji 😀 test' });
    });
  });
});