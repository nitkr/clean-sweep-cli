import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  getWpVersion,
  getPluginsCount,
  getThemesCount,
  checkWpContentWritable,
  checkDbConnection,
  getLastCoreUpdate,
} from '../src/commands/status';

describe('Status Module', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'status-test-'));
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('getWpVersion', () => {
    it('should extract version from valid version.php', () => {
      const wpDir = path.join(tempDir, 'wp');
      const versionContent = `<?php
/**
 * WordPress Version
 *
 * Contains version information for the core WordPress release.
 */
$wp_version = '6.4.3';
$wp_db_version = 56657;
`;
      fs.mkdirSync(path.join(wpDir, 'wp-includes'), { recursive: true });
      fs.writeFileSync(path.join(wpDir, 'wp-includes', 'version.php'), versionContent);

      const version = getWpVersion(wpDir);

      expect(version).toBe('6.4.3');
    });

    it('should return null when version.php does not exist', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(wpDir);

      const version = getWpVersion(wpDir);

      expect(version).toBeNull();
    });

    it('should return null for non-existent directory', () => {
      const wpDir = path.join(tempDir, 'nonexistent');

      const version = getWpVersion(wpDir);

      expect(version).toBeNull();
    });

    it('should return null when version.php has no $wp_version', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(path.join(wpDir, 'wp-includes'), { recursive: true });
      fs.writeFileSync(path.join(wpDir, 'wp-includes', 'version.php'), '<?php // empty version file');

      const version = getWpVersion(wpDir);

      expect(version).toBeNull();
    });

    it('should handle version with different quote styles', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(path.join(wpDir, 'wp-includes'), { recursive: true });
      fs.writeFileSync(path.join(wpDir, 'wp-includes', 'version.php'), "$wp_version = '5.9.1';");

      const version = getWpVersion(wpDir);

      expect(version).toBe('5.9.1');
    });

    it('should return first version when multiple definitions exist', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(path.join(wpDir, 'wp-includes'), { recursive: true });
      const versionContent = `<?php
$wp_version = '6.4.3';
$wp_version = '6.5.0';
$wp_db_version = 56657;
`;
      fs.writeFileSync(path.join(wpDir, 'wp-includes', 'version.php'), versionContent);

      const version = getWpVersion(wpDir);

      expect(version).toBe('6.4.3');
    });

    it('should match version even when similar patterns exist in comments', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(path.join(wpDir, 'wp-includes'), { recursive: true });
      const versionContent = `<?php
// $wp_version = '6.4.3';
/**
 * $wp_version = '6.5.0'
 */
# $wp_version = '6.6.0';
$wp_version = '6.4.3';
`;
      fs.writeFileSync(path.join(wpDir, 'wp-includes', 'version.php'), versionContent);

      const version = getWpVersion(wpDir);

      expect(version).toBe('6.4.3');
    });

    it('should match version even when commented version appears first', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(path.join(wpDir, 'wp-includes'), { recursive: true });
      const versionContent = `<?php
/**
 * Commented version: $wp_version = '5.0.0';
 */
$wp_version = '6.4.3';
`;
      fs.writeFileSync(path.join(wpDir, 'wp-includes', 'version.php'), versionContent);

      const version = getWpVersion(wpDir);

      expect(version).toBe('5.0.0');
    });
  });

  describe('getPluginsCount', () => {
    it('should count plugins in plugins directory', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'plugins'), { recursive: true });
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'plugins', 'plugin1'));
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'plugins', 'plugin2'));
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'plugins', 'plugin3'));

      const count = getPluginsCount(wpDir);

      expect(count).toBe(3);
    });

    it('should return 0 when plugins directory does not exist', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(wpDir);

      const count = getPluginsCount(wpDir);

      expect(count).toBe(0);
    });

    it('should return 0 for non-existent directory', () => {
      const wpDir = path.join(tempDir, 'nonexistent');

      const count = getPluginsCount(wpDir);

      expect(count).toBe(0);
    });

    it('should not count files as plugins', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'plugins'), { recursive: true });
      fs.writeFileSync(path.join(wpDir, 'wp-content', 'plugins', 'readme.txt'), 'readme');
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'plugins', 'real-plugin'));

      const count = getPluginsCount(wpDir);

      expect(count).toBe(1);
    });

    it('should return 0 for empty plugins directory', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'plugins'), { recursive: true });

      const count = getPluginsCount(wpDir);

      expect(count).toBe(0);
    });

    it('should only count directories when mixed with files', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'plugins'), { recursive: true });
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'plugins', 'akismet'));
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'plugins', 'hello-dolly'));
      fs.writeFileSync(path.join(wpDir, 'wp-content', 'plugins', 'readme.txt'), 'readme');
      fs.writeFileSync(path.join(wpDir, 'wp-content', 'plugins', 'index.php'), '<?php');
      fs.writeFileSync(path.join(wpDir, 'wp-content', 'plugins', 'license.txt'), 'license');

      const count = getPluginsCount(wpDir);

      expect(count).toBe(2);
    });

    it('should count hidden directories as plugins', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'plugins'), { recursive: true });
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'plugins', 'visible-plugin'));
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'plugins', '.hidden-plugin'));
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'plugins', '..parent-hidden'));

      const count = getPluginsCount(wpDir);

      expect(count).toBe(3);
    });
  });

  describe('getThemesCount', () => {
    it('should count themes in themes directory', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'themes'), { recursive: true });
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'themes', 'twentytwenty'));
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'themes', 'twentytwentyone'));

      const count = getThemesCount(wpDir);

      expect(count).toBe(2);
    });

    it('should return 0 when themes directory does not exist', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(wpDir);

      const count = getThemesCount(wpDir);

      expect(count).toBe(0);
    });

    it('should return 0 for non-existent directory', () => {
      const wpDir = path.join(tempDir, 'nonexistent');

      const count = getThemesCount(wpDir);

      expect(count).toBe(0);
    });

    it('should not count files as themes', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'themes'), { recursive: true });
      fs.writeFileSync(path.join(wpDir, 'wp-content', 'themes', 'style.css'), '/* Theme */');
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'themes', 'mytheme'));

      const count = getThemesCount(wpDir);

      expect(count).toBe(1);
    });

    it('should return 0 for empty themes directory', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'themes'), { recursive: true });

      const count = getThemesCount(wpDir);

      expect(count).toBe(0);
    });

    it('should only count directories when mixed with files', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'themes'), { recursive: true });
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'themes', 'twentytwentyfour'));
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'themes', 'mytheme'));
      fs.writeFileSync(path.join(wpDir, 'wp-content', 'themes', 'style.css'), '/* Theme */');
      fs.writeFileSync(path.join(wpDir, 'wp-content', 'themes', 'functions.php'), '<?php');
      fs.writeFileSync(path.join(wpDir, 'wp-content', 'themes', 'readme.txt'), 'readme');

      const count = getThemesCount(wpDir);

      expect(count).toBe(2);
    });

    it('should count hidden directories as themes', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'themes'), { recursive: true });
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'themes', 'twentytwentyfour'));
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'themes', '.hidden-theme'));
      fs.mkdirSync(path.join(wpDir, 'wp-content', 'themes', '..dotdot-theme'));

      const count = getThemesCount(wpDir);

      expect(count).toBe(3);
    });
  });

  describe('checkWpContentWritable', () => {
    it('should return true when wp-content is writable', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(path.join(wpDir, 'wp-content'), { recursive: true });

      const writable = checkWpContentWritable(wpDir);

      expect(writable).toBe(true);
    });

    it('should return false when wp-content directory does not exist', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(wpDir);

      const writable = checkWpContentWritable(wpDir);

      expect(writable).toBe(false);
    });

    it('should return false for non-existent directory', () => {
      const wpDir = path.join(tempDir, 'nonexistent');

      const writable = checkWpContentWritable(wpDir);

      expect(writable).toBe(false);
    });

    it('should return false when wp-content is not writable', () => {
      const wpDir = path.join(tempDir, 'wp');
      const wpContentDir = path.join(wpDir, 'wp-content');
      fs.mkdirSync(wpContentDir, { recursive: true });
      fs.chmodSync(wpContentDir, 0o444);

      const writable = checkWpContentWritable(wpDir);

      fs.chmodSync(wpContentDir, 0o755);
      expect(writable).toBe(false);
    });

    it('should return false when testing root directory without wp-content', () => {
      const rootDir = path.join(tempDir, 'root');
      fs.mkdirSync(rootDir, { recursive: true });

      const writable = checkWpContentWritable(rootDir);

      expect(writable).toBe(false);
    });
  });

  describe('checkDbConnection', () => {
    it('should return true when db config exists in wp-config.php', () => {
      const wpDir = path.join(tempDir, 'wp');
      const wpConfigContent = `<?php
define('DB_NAME', 'wordpress');
define('DB_USER', 'root');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8');
`;
      fs.mkdirSync(wpDir);
      fs.writeFileSync(path.join(wpDir, 'wp-config.php'), wpConfigContent);

      const connected = checkDbConnection(wpDir);

      expect(connected).toBe(true);
    });

    it('should return false when wp-config.php does not exist', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(wpDir);

      const connected = checkDbConnection(wpDir);

      expect(connected).toBe(false);
    });

    it('should return false for non-existent directory', () => {
      const wpDir = path.join(tempDir, 'nonexistent');

      const connected = checkDbConnection(wpDir);

      expect(connected).toBe(false);
    });

    it('should return false when DB_NAME is missing', () => {
      const wpDir = path.join(tempDir, 'wp');
      const wpConfigContent = `<?php
define('DB_USER', 'root');
define('DB_HOST', 'localhost');
`;
      fs.mkdirSync(wpDir);
      fs.writeFileSync(path.join(wpDir, 'wp-config.php'), wpConfigContent);

      const connected = checkDbConnection(wpDir);

      expect(connected).toBe(false);
    });

    it('should return false when DB_USER is missing', () => {
      const wpDir = path.join(tempDir, 'wp');
      const wpConfigContent = `<?php
define('DB_NAME', 'wordpress');
define('DB_HOST', 'localhost');
`;
      fs.mkdirSync(wpDir);
      fs.writeFileSync(path.join(wpDir, 'wp-config.php'), wpConfigContent);

      const connected = checkDbConnection(wpDir);

      expect(connected).toBe(false);
    });

    it('should return true when DB_HOST uses custom port', () => {
      const wpDir = path.join(tempDir, 'wp');
      const wpConfigContent = `<?php
define('DB_NAME', 'wordpress');
define('DB_USER', 'root');
define('DB_HOST', 'localhost:3306');
`;
      fs.mkdirSync(wpDir);
      fs.writeFileSync(path.join(wpDir, 'wp-config.php'), wpConfigContent);

      const connected = checkDbConnection(wpDir);

      expect(connected).toBe(true);
    });

    it('should return false when db values are empty', () => {
      const wpDir = path.join(tempDir, 'wp');
      const wpConfigContent = `<?php
define('DB_NAME', '');
define('DB_USER', 'root');
`;
      fs.mkdirSync(wpDir);
      fs.writeFileSync(path.join(wpDir, 'wp-config.php'), wpConfigContent);

      const connected = checkDbConnection(wpDir);

      expect(connected).toBe(false);
    });

    it('should handle wp-config with different spacing styles', () => {
      const wpDir = path.join(tempDir, 'wp');
      const wpConfigContent = `<?php
define( 'DB_NAME', 'myblog' );
define( 'DB_USER', 'admin' );
`;
      fs.mkdirSync(wpDir);
      fs.writeFileSync(path.join(wpDir, 'wp-config.php'), wpConfigContent);

      const connected = checkDbConnection(wpDir);

      expect(connected).toBe(true);
    });
  });

  describe('getLastCoreUpdate', () => {
    it('should return ISO date when last_update_check exists', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(path.join(wpDir, 'wp-admin', 'includes'), { recursive: true });
      fs.mkdirSync(path.join(wpDir, 'wp-includes'), { recursive: true });
      fs.writeFileSync(path.join(wpDir, 'wp-admin', 'includes', 'update.php'), '<?php // update');
      fs.writeFileSync(path.join(wpDir, 'wp-includes', 'option.php'), "<?php\n\$options['last_update_check'] = '2024-01-15';");

      const result = getLastCoreUpdate(wpDir);

      expect(result).not.toBeNull();
      expect(new Date(result!).toISOString()).toBe(result);
    });

    it('should return null when update.php does not exist', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(path.join(wpDir, 'wp-admin', 'includes'), { recursive: true });

      const result = getLastCoreUpdate(wpDir);

      expect(result).toBeNull();
    });

    it('should return null when option.php does not exist', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(path.join(wpDir, 'wp-admin', 'includes'), { recursive: true });
      fs.writeFileSync(path.join(wpDir, 'wp-admin', 'includes', 'update.php'), '<?php // update');

      const result = getLastCoreUpdate(wpDir);

      expect(result).toBeNull();
    });

    it('should return null when last_update_check not in option.php', () => {
      const wpDir = path.join(tempDir, 'wp');
      fs.mkdirSync(path.join(wpDir, 'wp-admin', 'includes'), { recursive: true });
      fs.mkdirSync(path.join(wpDir, 'wp-includes'), { recursive: true });
      fs.writeFileSync(path.join(wpDir, 'wp-admin', 'includes', 'update.php'), '<?php // update');
      fs.writeFileSync(path.join(wpDir, 'wp-includes', 'option.php'), "<?php\n\$options['other_option'] = 'value';");

      const result = getLastCoreUpdate(wpDir);

      expect(result).toBeNull();
    });

    it('should return null for non-existent directory', () => {
      const wpDir = path.join(tempDir, 'nonexistent');

      const result = getLastCoreUpdate(wpDir);

      expect(result).toBeNull();
    });
  });
});