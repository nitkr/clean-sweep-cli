import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { Command } from 'commander';

import {
  registerLicensesCheckCommand,
  checkLicenses,
  isGplCompatible,
} from '../src/commands/licenses-check';

function createTestCliOptions(
  overrides: Partial<{
    dryRun: boolean;
    force: boolean;
    json: boolean;
    path: string;
    verbose: boolean;
    logLevel: string;
  }> = {}
) {
  return () => ({
    dryRun: true,
    force: false,
    json: false,
    path: process.cwd(),
    verbose: false,
    logLevel: 'error' as string,
    checkVulnerabilities: false,
    checkIntegrity: false,
    findUnknown: false,
    report: false,
    htmlReport: false,
    ...overrides,
  });
}

function createWpStructure(
  baseDir: string,
  plugins: Array<{ slug: string; header: string }>,
  themes: Array<{ slug: string; header: string }>
) {
  for (const plugin of plugins) {
    const pluginDir = path.join(baseDir, 'wp-content', 'plugins', plugin.slug);
    fs.mkdirSync(pluginDir, { recursive: true });
    const mainFile = path.join(pluginDir, `${plugin.slug}.php`);
    fs.writeFileSync(mainFile, `<?php\n${plugin.header}\n`);
  }

  for (const theme of themes) {
    const themeDir = path.join(baseDir, 'wp-content', 'themes', theme.slug);
    fs.mkdirSync(themeDir, { recursive: true });
    fs.writeFileSync(path.join(themeDir, 'style.css'), theme.header);
  }
}

describe('Licenses Check Command', () => {
  let tempDir: string;
  let consoleSpy: ReturnType<typeof jest.spyOn>;
  let consoleErrorSpy: ReturnType<typeof jest.spyOn>;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'licenses-check-test-'));
    consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
    consoleSpy.mockRestore();
    consoleErrorSpy.mockRestore();
  });

  function createProgram() {
    const program = new Command();
    program.exitOverride();
    return program;
  }

  describe('isGplCompatible', () => {
    it('should match GPL v2 or later variants', () => {
      expect(isGplCompatible('GPL v2 or later')).toBe(true);
      expect(isGplCompatible('gpl-2.0-or-later')).toBe(true);
      expect(isGplCompatible('GPL-2.0+')).toBe(true);
      expect(isGplCompatible('GPL-2.0')).toBe(true);
      expect(isGplCompatible('GPL2')).toBe(true);
    });

    it('should match GPL v3 variants', () => {
      expect(isGplCompatible('GPL-3.0-or-later')).toBe(true);
      expect(isGplCompatible('GPL-3.0+')).toBe(true);
      expect(isGplCompatible('GPL-3.0')).toBe(true);
      expect(isGplCompatible('GPL v3 or later')).toBe(true);
    });

    it('should match MIT license', () => {
      expect(isGplCompatible('MIT')).toBe(true);
      expect(isGplCompatible('mit')).toBe(true);
    });

    it('should match BSD licenses', () => {
      expect(isGplCompatible('BSD-2-Clause')).toBe(true);
      expect(isGplCompatible('BSD-3-Clause')).toBe(true);
      expect(isGplCompatible('BSD')).toBe(true);
    });

    it('should match Apache 2.0', () => {
      expect(isGplCompatible('Apache-2.0')).toBe(true);
      expect(isGplCompatible('Apache 2.0')).toBe(true);
    });

    it('should reject proprietary licenses', () => {
      expect(isGplCompatible('Proprietary')).toBe(false);
      expect(isGplCompatible('Commercial')).toBe(false);
      expect(isGplCompatible('All Rights Reserved')).toBe(false);
    });

    it('should reject empty license', () => {
      expect(isGplCompatible('')).toBe(false);
    });

    it('should be case-insensitive', () => {
      expect(isGplCompatible('GPL v2 or later')).toBe(true);
      expect(isGplCompatible('gpl v2 or later')).toBe(true);
      expect(isGplCompatible('GPL V2 OR LATER')).toBe(true);
    });
  });

  describe('argument validation', () => {
    it('should fail for non-existent path', async () => {
      const program = createProgram();
      registerLicensesCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'licenses:check',
          '--path', '/nonexistent/path/12345',
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      expect(mockExit).toHaveBeenCalledWith(1);
      mockExit.mockRestore();
    });

    it('should fail for non-directory path', async () => {
      const filePath = path.join(tempDir, 'file.txt');
      fs.writeFileSync(filePath, 'content');

      const program = createProgram();
      registerLicensesCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'licenses:check',
          '--path', filePath,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      expect(mockExit).toHaveBeenCalledWith(1);
      mockExit.mockRestore();
    });
  });

  describe('checkLicenses', () => {
    it('should return empty results when no wp-content directory exists', () => {
      const result = checkLicenses(tempDir);

      expect(result.pluginsChecked).toBe(0);
      expect(result.themesChecked).toBe(0);
      expect(result.totalItems).toBe(0);
      expect(result.licenses).toHaveLength(0);
      expect(result.hasIssues).toBe(false);
    });

    it('should detect GPL-compatible plugin license', () => {
      createWpStructure(
        tempDir,
        [
          {
            slug: 'gpl-plugin',
            header: `/**
 * Plugin Name: GPL Plugin
 * Version: 1.0.0
 * License: GPL v2 or later
 */`,
          },
        ],
        []
      );

      const result = checkLicenses(tempDir);

      expect(result.pluginsChecked).toBe(1);
      expect(result.totalItems).toBe(1);
      expect(result.licenses[0].name).toBe('GPL Plugin');
      expect(result.licenses[0].gplCompatible).toBe(true);
      expect(result.gplCompatible).toBe(1);
      expect(result.hasIssues).toBe(false);
    });

    it('should detect non-GPL plugin license', () => {
      createWpStructure(
        tempDir,
        [
          {
            slug: 'premium-plugin',
            header: `/**
 * Plugin Name: Premium Plugin
 * Version: 2.0.0
 * License: Proprietary
 */`,
          },
        ],
        []
      );

      const result = checkLicenses(tempDir);

      expect(result.pluginsChecked).toBe(1);
      expect(result.gplIncompatible).toBe(1);
      expect(result.hasIssues).toBe(true);
      expect(result.issues[0].type).toBe('non_gpl');
      expect(result.issues[0].severity).toBe('HIGH');
    });

    it('should detect missing license on plugin', () => {
      createWpStructure(
        tempDir,
        [
          {
            slug: 'no-license-plugin',
            header: `/**
 * Plugin Name: No License Plugin
 * Version: 1.0.0
 */`,
          },
        ],
        []
      );

      const result = checkLicenses(tempDir);

      expect(result.pluginsChecked).toBe(1);
      expect(result.hasIssues).toBe(true);
      expect(result.issues[0].type).toBe('missing_license');
      expect(result.issues[0].severity).toBe('MEDIUM');
    });

    it('should detect GPL-compatible theme license', () => {
      createWpStructure(
        tempDir,
        [],
        [
          {
            slug: 'gpl-theme',
            header: `/*
Theme Name: GPL Theme
Version: 1.0.0
License: GPL-2.0-or-later
*/`,
          },
        ]
      );

      const result = checkLicenses(tempDir);

      expect(result.themesChecked).toBe(1);
      expect(result.totalItems).toBe(1);
      expect(result.licenses[0].name).toBe('GPL Theme');
      expect(result.licenses[0].type).toBe('theme');
      expect(result.licenses[0].gplCompatible).toBe(true);
      expect(result.hasIssues).toBe(false);
    });

    it('should detect non-GPL theme license', () => {
      createWpStructure(
        tempDir,
        [],
        [
          {
            slug: 'premium-theme',
            header: `/*
Theme Name: Premium Theme
Version: 1.0.0
License: Commercial
*/`,
          },
        ]
      );

      const result = checkLicenses(tempDir);

      expect(result.themesChecked).toBe(1);
      expect(result.gplIncompatible).toBe(1);
      expect(result.hasIssues).toBe(true);
      expect(result.issues[0].type).toBe('non_gpl');
      expect(result.issues[0].severity).toBe('HIGH');
    });

    it('should detect missing license on theme', () => {
      createWpStructure(
        tempDir,
        [],
        [
          {
            slug: 'no-license-theme',
            header: `/*
Theme Name: No License Theme
Author: Test
*/`,
          },
        ]
      );

      const result = checkLicenses(tempDir);

      expect(result.themesChecked).toBe(1);
      expect(result.hasIssues).toBe(true);
      expect(result.issues[0].type).toBe('missing_license');
      expect(result.issues[0].severity).toBe('MEDIUM');
    });

    it('should check multiple plugins and themes', () => {
      createWpStructure(
        tempDir,
        [
          {
            slug: 'gpl-plugin',
            header: `/**
 * Plugin Name: GPL Plugin
 * License: GPL-2.0-or-later
 */`,
          },
          {
            slug: 'mit-plugin',
            header: `/**
 * Plugin Name: MIT Plugin
 * License: MIT
 */`,
          },
          {
            slug: 'proprietary-plugin',
            header: `/**
 * Plugin Name: Proprietary Plugin
 * License: Proprietary
 */`,
          },
        ],
        [
          {
            slug: 'gpl-theme',
            header: `/*
Theme Name: GPL Theme
License: GPL v2 or later
*/`,
          },
          {
            slug: 'no-license-theme',
            header: `/*
Theme Name: No License Theme
Author: Test
*/`,
          },
        ]
      );

      const result = checkLicenses(tempDir);

      expect(result.pluginsChecked).toBe(3);
      expect(result.themesChecked).toBe(2);
      expect(result.totalItems).toBe(5);
      expect(result.gplCompatible).toBe(3);
      expect(result.gplIncompatible).toBe(1);
      expect(result.hasIssues).toBe(true);
      expect(result.issues.length).toBe(2);
    });

    it('should build byLicense breakdown', () => {
      createWpStructure(
        tempDir,
        [
          {
            slug: 'gpl-plugin',
            header: `/**
 * Plugin Name: GPL Plugin
 * License: GPL-2.0-or-later
 */`,
          },
          {
            slug: 'mit-plugin',
            header: `/**
 * Plugin Name: MIT Plugin
 * License: MIT
 */`,
          },
        ],
        []
      );

      const result = checkLicenses(tempDir);

      expect(result.byLicense['GPL-2.0-or-later']).toBe(1);
      expect(result.byLicense['MIT']).toBe(1);
    });

    it('should build bySeverity breakdown', () => {
      createWpStructure(
        tempDir,
        [
          {
            slug: 'premium-plugin',
            header: `/**
 * Plugin Name: Premium Plugin
 * License: Proprietary
 */`,
          },
          {
            slug: 'no-license-plugin',
            header: `/**
 * Plugin Name: No License Plugin
 */`,
          },
        ],
        []
      );

      const result = checkLicenses(tempDir);

      expect(result.bySeverity['HIGH']).toBe(1);
      expect(result.bySeverity['MEDIUM']).toBe(1);
    });

    it('should extract version, description, and author from plugin header', () => {
      createWpStructure(
        tempDir,
        [
          {
            slug: 'full-header',
            header: `/**
 * Plugin Name: Full Header Plugin
 * Version: 3.1.4
 * Description: A plugin with all headers
 * Author: John Doe
 * License: GPL-2.0-or-later
 */`,
          },
        ],
        []
      );

      const result = checkLicenses(tempDir);

      expect(result.licenses[0].version).toBe('3.1.4');
      expect(result.licenses[0].description).toBe('A plugin with all headers');
      expect(result.licenses[0].author).toBe('John Doe');
    });

    it('should skip plugin directories without main file', () => {
      const pluginDir = path.join(tempDir, 'wp-content', 'plugins', 'empty-plugin');
      fs.mkdirSync(pluginDir, { recursive: true });
      fs.writeFileSync(path.join(pluginDir, 'readme.txt'), 'Not a plugin file');

      const result = checkLicenses(tempDir);

      expect(result.pluginsChecked).toBe(0);
    });

    it('should find alternative plugin main files', () => {
      const pluginDir = path.join(tempDir, 'wp-content', 'plugins', 'index-plugin');
      fs.mkdirSync(pluginDir, { recursive: true });
      fs.writeFileSync(
        path.join(pluginDir, 'index.php'),
        `<?php\n/**\n * Plugin Name: Index Plugin\n * License: MIT\n */`
      );

      const result = checkLicenses(tempDir);

      expect(result.pluginsChecked).toBe(1);
      expect(result.licenses[0].name).toBe('Index Plugin');
    });

    it('should work with existing wp-complete fixture', () => {
      const fixturePath = path.join(__dirname, '..', 'test', 'fixtures', 'wp-complete');
      const result = checkLicenses(fixturePath);

      expect(result.pluginsChecked).toBe(1);
      expect(result.themesChecked).toBe(1);
      expect(result.totalItems).toBe(2);
    });

    it('should work with existing clean-wp fixture', () => {
      const fixturePath = path.join(__dirname, '..', 'test', 'fixtures', 'clean-wp');
      const result = checkLicenses(fixturePath);

      expect(result.pluginsChecked).toBe(1);
      expect(result.themesChecked).toBe(1);
      expect(result.totalItems).toBe(2);
    });
  });

  describe('JSON output', () => {
    it('should produce valid JSON with --json flag', async () => {
      createWpStructure(
        tempDir,
        [
          {
            slug: 'test-plugin',
            header: `/**
 * Plugin Name: Test Plugin
 * License: GPL-2.0-or-later
 */`,
          },
        ],
        []
      );

      const program = createProgram();
      registerLicensesCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'licenses:check',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);

      expect(result).toHaveProperty('path');
      expect(result).toHaveProperty('pluginsChecked');
      expect(result).toHaveProperty('themesChecked');
      expect(result).toHaveProperty('totalItems');
      expect(result).toHaveProperty('gplCompatible');
      expect(result).toHaveProperty('gplIncompatible');
      expect(result).toHaveProperty('licenses');
      expect(result).toHaveProperty('issues');
      expect(result).toHaveProperty('hasIssues');
      expect(result).toHaveProperty('bySeverity');
      expect(result).toHaveProperty('byLicense');
      mockExit.mockRestore();
    });

    it('should produce valid JSON for error case', async () => {
      const program = createProgram();
      registerLicensesCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'licenses:check',
          '--path', '/nonexistent/path/12345',
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      expect(() => JSON.parse(output)).not.toThrow();
      expect(mockExit).toHaveBeenCalledWith(1);
      mockExit.mockRestore();
    });

    it('should produce valid JSON when no items found', async () => {
      const program = createProgram();
      registerLicensesCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'licenses:check',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.totalItems).toBe(0);
      expect(result.licenses).toHaveLength(0);
      expect(result.hasIssues).toBe(false);
      mockExit.mockRestore();
    });
  });

  describe('human-readable output', () => {
    it('should print check info without --json', async () => {
      createWpStructure(
        tempDir,
        [
          {
            slug: 'test-plugin',
            header: `/**
 * Plugin Name: Test Plugin
 * License: GPL-2.0-or-later
 */`,
          },
        ],
        []
      );

      const program = createProgram();
      registerLicensesCheckCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'licenses:check',
          '--path', tempDir,
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const allOutput = consoleSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('Checking licenses');
      expect(allOutput).toContain('Plugins checked');
      expect(allOutput).toContain('Themes checked');
      expect(allOutput).toContain('Test Plugin');
      expect(allOutput).toContain('GPL-compatible');
      mockExit.mockRestore();
    });

    it('should display issues with severity tags', async () => {
      createWpStructure(
        tempDir,
        [
          {
            slug: 'premium-plugin',
            header: `/**
 * Plugin Name: Premium Plugin
 * License: Proprietary
 */`,
          },
        ],
        []
      );

      const program = createProgram();
      registerLicensesCheckCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'licenses:check',
          '--path', tempDir,
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const allOutput = consoleSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('[HIGH]');
      expect(allOutput).toContain('non-GPL-compatible');
      expect(allOutput).toContain('Severity breakdown');
      mockExit.mockRestore();
    });

    it('should show no items message when directory is empty', async () => {
      const program = createProgram();
      registerLicensesCheckCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'licenses:check',
          '--path', tempDir,
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const allOutput = consoleSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('No plugins or themes found');
      mockExit.mockRestore();
    });
  });

  describe('exit codes', () => {
    it('should exit 1 when non-GPL license found', async () => {
      createWpStructure(
        tempDir,
        [
          {
            slug: 'premium-plugin',
            header: `/**
 * Plugin Name: Premium Plugin
 * License: Proprietary
 */`,
          },
        ],
        []
      );

      const program = createProgram();
      registerLicensesCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'licenses:check',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      expect(mockExit).toHaveBeenCalledWith(1);
      mockExit.mockRestore();
    });

    it('should exit 0 when all licenses are GPL-compatible', async () => {
      createWpStructure(
        tempDir,
        [
          {
            slug: 'gpl-plugin',
            header: `/**
 * Plugin Name: GPL Plugin
 * License: GPL-2.0-or-later
 */`,
          },
        ],
        []
      );

      const program = createProgram();
      registerLicensesCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'licenses:check',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      expect(mockExit).toHaveBeenCalledWith(0);
      mockExit.mockRestore();
    });

    it('should exit 0 when no items found', async () => {
      const program = createProgram();
      registerLicensesCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'licenses:check',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      expect(mockExit).toHaveBeenCalledWith(0);
      mockExit.mockRestore();
    });

    it('should exit 0 for missing license (medium severity only)', async () => {
      createWpStructure(
        tempDir,
        [
          {
            slug: 'no-license-plugin',
            header: `/**
 * Plugin Name: No License Plugin
 */`,
          },
        ],
        []
      );

      const program = createProgram();
      registerLicensesCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'licenses:check',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      expect(mockExit).toHaveBeenCalledWith(0);
      mockExit.mockRestore();
    });
  });
});
