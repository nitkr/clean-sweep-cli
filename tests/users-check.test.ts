import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { Command } from 'commander';

import {
  registerUsersCheckCommand,
  checkUsers,
  parsePhpUsersExport,
  parseSqlExport,
  detectSuspiciousLogins,
  checkDefaultAdmin,
  checkDefaultEmail,
  checkMultipleAdmins,
  checkWeakRoleAssignment,
} from '../src/commands/users-check';

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
    ...overrides,
  });
}

describe('Users Check Command', () => {
  let tempDir: string;
  let consoleSpy: ReturnType<typeof jest.spyOn>;
  let consoleErrorSpy: ReturnType<typeof jest.spyOn>;
  let consoleWarnSpy: ReturnType<typeof jest.spyOn>;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'users-check-test-'));
    consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
    consoleSpy.mockRestore();
    consoleErrorSpy.mockRestore();
    consoleWarnSpy.mockRestore();
  });

  // Helper to create minimal WordPress installation for CLI tests
  function createWordPressInstall(dir: string): void {
    const wpConfigContent = [
      "<?php",
      "define('DB_NAME', 'test_db');",
      "define('DB_USER', 'test_user');",
      "define('DB_PASSWORD', 'test_pass');",
      "define('DB_HOST', 'localhost');",
      "$table_prefix = 'wp_';",
    ].join('\n');
    fs.writeFileSync(path.join(dir, 'wp-config.php'), wpConfigContent);
  }

  function createProgram() {
    const program = new Command();
    program.exitOverride();
    return program;
  }

  describe('argument validation', () => {
    it('should fail for non-existent path', async () => {
      const program = createProgram();
      registerUsersCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'users:check',
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
      registerUsersCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'users:check',
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

  describe('parsePhpUsersExport', () => {
    it('should parse PHP stdClass user export', () => {
      const content = [
        "$user = new stdClass();",
        "$user->ID = '1';",
        "$user->user_login = 'admin';",
        "$user->user_email = 'admin@example.com';",
        "$user->display_name = 'Administrator';",
        "$user->roles = 'administrator';",
        "",
        "$user2 = new stdClass();",
        "$user2->ID = '2';",
        "$user2->user_login = 'editor1';",
        "$user2->user_email = 'editor@site.com';",
        "$user2->display_name = 'Editor One';",
        "$user2->roles = 'editor';",
      ].join('\n');

      const users = parsePhpUsersExport(content);

      expect(users).toHaveLength(2);
      expect(users[0].id).toBe(1);
      expect(users[0].login).toBe('admin');
      expect(users[0].email).toBe('admin@example.com');
      expect(users[1].login).toBe('editor1');
    });

    it('should parse PHP INSERT statements', () => {
      const content = "INSERT INTO `wp_users` (`id`, `user_login`, `user_email`, `display_name`) VALUES (1, 'admin', 'admin@example.com', 'Administrator')";

      const users = parsePhpUsersExport(content);

      expect(users).toHaveLength(1);
      expect(users[0].id).toBe(1);
      expect(users[0].login).toBe('admin');
    });

    it('should return empty array for empty content', () => {
      const users = parsePhpUsersExport('');
      expect(users).toHaveLength(0);
    });

    it('should return empty array for unrelated content', () => {
      const users = parsePhpUsersExport('<?php echo "hello world"; ?>');
      expect(users).toHaveLength(0);
    });
  });

  describe('parseSqlExport', () => {
    it('should parse SQL INSERT statements for users', () => {
      const content = [
        "INSERT INTO `wp_users` (`id`, `user_login`, `user_email`, `display_name`) VALUES (1, 'admin', 'admin@site.com', 'Admin');",
        "INSERT INTO `wp_users` (`id`, `user_login`, `user_email`, `display_name`) VALUES (2, 'john', 'john@site.com', 'John');",
      ].join('\n');

      const users = parseSqlExport(content);

      expect(users).toHaveLength(2);
      expect(users[0].login).toBe('admin');
      expect(users[1].login).toBe('john');
    });

    it('should extract roles from wp_usermeta', () => {
      const content = [
        "INSERT INTO `wp_users` (`id`, `user_login`, `user_email`, `display_name`) VALUES (1, 'admin', 'admin@site.com', 'Admin');",
        "INSERT INTO `wp_usermeta` (`user_id`, `meta_key`, `meta_value`) VALUES (1, 'wp_capabilities', 'a:1:{s:13:\"administrator\";b:1;}');",
      ].join('\n');

      const users = parseSqlExport(content);

      expect(users).toHaveLength(1);
      expect(users[0].roles).toContain('administrator');
    });

    it('should return empty array for non-SQL content', () => {
      const users = parseSqlExport('<?php echo "hello"; ?>');
      expect(users).toHaveLength(0);
    });
  });

  describe('checkDefaultAdmin', () => {
    it('should flag default admin username', () => {
      const users = [
        { id: 1, login: 'admin', email: 'admin@site.com', displayName: 'Admin', roles: ['administrator'] },
      ];

      const issue = checkDefaultAdmin(users);

      expect(issue).not.toBeNull();
      expect(issue?.type).toBe('default_admin');
      expect(issue?.severity).toBe('HIGH');
    });

    it('should not flag non-default admin username', () => {
      const users = [
        { id: 1, login: 'mysite_admin', email: 'admin@site.com', displayName: 'Admin', roles: ['administrator'] },
      ];

      const issue = checkDefaultAdmin(users);

      expect(issue).toBeNull();
    });

    it('should be case-insensitive', () => {
      const users = [
        { id: 1, login: 'Admin', email: 'admin@site.com', displayName: 'Admin', roles: ['administrator'] },
      ];

      const issue = checkDefaultAdmin(users);

      expect(issue).not.toBeNull();
    });
  });

  describe('checkDefaultEmail', () => {
    it('should flag admin@example.com email', () => {
      const users = [
        { id: 1, login: 'john', email: 'admin@example.com', displayName: 'John', roles: ['subscriber'] },
      ];

      const issues = checkDefaultEmail(users);

      expect(issues).toHaveLength(1);
      expect(issues[0].type).toBe('admin_default_email');
      expect(issues[0].severity).toBe('HIGH');
    });

    it('should be case-insensitive for email', () => {
      const users = [
        { id: 1, login: 'john', email: 'Admin@Example.Com', displayName: 'John', roles: ['subscriber'] },
      ];

      const issues = checkDefaultEmail(users);

      expect(issues).toHaveLength(1);
    });

    it('should not flag real emails', () => {
      const users = [
        { id: 1, login: 'john', email: 'john@realsite.com', displayName: 'John', roles: ['subscriber'] },
      ];

      const issues = checkDefaultEmail(users);

      expect(issues).toHaveLength(0);
    });
  });

  describe('checkMultipleAdmins', () => {
    it('should flag multiple administrator accounts', () => {
      const users = [
        { id: 1, login: 'admin1', email: 'a@b.com', displayName: 'A1', roles: ['administrator'] },
        { id: 2, login: 'admin2', email: 'b@b.com', displayName: 'A2', roles: ['administrator'] },
      ];

      const issues = checkMultipleAdmins(users);

      expect(issues).toHaveLength(2);
      expect(issues[0].type).toBe('multiple_admins');
      expect(issues[0].severity).toBe('LOW');
    });

    it('should not flag single admin', () => {
      const users = [
        { id: 1, login: 'admin1', email: 'a@b.com', displayName: 'A1', roles: ['administrator'] },
        { id: 2, login: 'editor1', email: 'b@b.com', displayName: 'E1', roles: ['editor'] },
      ];

      const issues = checkMultipleAdmins(users);

      expect(issues).toHaveLength(0);
    });
  });

  describe('detectSuspiciousLogins', () => {
    it('should flag suspicious login names', () => {
      const users = [
        { id: 1, login: 'test', email: 'a@b.com', displayName: 'Test', roles: ['subscriber'] },
        { id: 2, login: 'root', email: 'b@b.com', displayName: 'Root', roles: ['administrator'] },
        { id: 3, login: 'webmaster', email: 'c@b.com', displayName: 'WM', roles: ['subscriber'] },
      ];

      const issues = detectSuspiciousLogins(users);

      expect(issues.length).toBeGreaterThanOrEqual(3);
      expect(issues.every((i) => i.type === 'suspicious_login')).toBe(true);
      expect(issues.every((i) => i.severity === 'MEDIUM')).toBe(true);
    });

    it('should not flag non-suspicious login names', () => {
      const users = [
        { id: 1, login: 'john_smith', email: 'a@b.com', displayName: 'John', roles: ['editor'] },
        { id: 2, login: 'marketing_lead', email: 'b@b.com', displayName: 'ML', roles: ['author'] },
      ];

      const issues = detectSuspiciousLogins(users);

      expect(issues).toHaveLength(0);
    });

    it('should flag "admin" numeric variants but not plain "admin"', () => {
      const users = [
        { id: 1, login: 'admin', email: 'a@b.com', displayName: 'Admin', roles: ['administrator'] },
        { id: 2, login: 'admin2', email: 'b@b.com', displayName: 'Admin2', roles: ['administrator'] },
      ];

      const issues = detectSuspiciousLogins(users);

      expect(issues).toHaveLength(1);
      expect(issues[0].user.login).toBe('admin2');
    });
  });

  describe('checkWeakRoleAssignment', () => {
    it('should flag unrecognized roles', () => {
      const users = [
        { id: 1, login: 'user1', email: 'a@b.com', displayName: 'User1', roles: ['super_hacker'] },
      ];

      const issues = checkWeakRoleAssignment(users);

      expect(issues).toHaveLength(1);
      expect(issues[0].type).toBe('weak_role_assignment');
    });

    it('should not flag valid WordPress roles', () => {
      const users = [
        { id: 1, login: 'user1', email: 'a@b.com', displayName: 'User1', roles: ['administrator'] },
        { id: 2, login: 'user2', email: 'b@b.com', displayName: 'User2', roles: ['editor'] },
      ];

      const issues = checkWeakRoleAssignment(users);

      expect(issues).toHaveLength(0);
    });

    it('should not flag users with no roles', () => {
      const users = [
        { id: 1, login: 'user1', email: 'a@b.com', displayName: 'User1', roles: [] },
      ];

      const issues = checkWeakRoleAssignment(users);

      expect(issues).toHaveLength(0);
    });
  });

  describe('checkUsers', () => {
    it('should return no data when no user files exist', () => {
      const result = checkUsers(tempDir);

      expect(result.usersFound).toBe(false);
      expect(result.source).toBe('none');
      expect(result.users).toHaveLength(0);
      expect(result.hasIssues).toBe(false);
    });

    it('should parse wp-users.php file', () => {
      const content = [
        "$user = new stdClass();",
        "$user->ID = '1';",
        "$user->user_login = 'mysite_admin';",
        "$user->user_email = 'real@site.com';",
        "$user->display_name = 'Site Admin';",
        "$user->roles = 'administrator';",
      ].join('\n');
      fs.writeFileSync(path.join(tempDir, 'wp-users.php'), content);

      const result = checkUsers(tempDir);

      expect(result.usersFound).toBe(true);
      expect(result.source).toBe('wp-users.php');
      expect(result.users).toHaveLength(1);
      expect(result.users[0].login).toBe('mysite_admin');
    });

    it('should detect SQL export files with "user" in name', () => {
      const content = [
        "INSERT INTO `wp_users` (`id`, `user_login`, `user_email`, `display_name`) VALUES (1, 'john', 'john@site.com', 'John');",
      ].join('\n');
      fs.writeFileSync(path.join(tempDir, 'db-users-export.sql'), content);

      const result = checkUsers(tempDir);

      expect(result.usersFound).toBe(true);
      expect(result.source).toBe('sql-export');
    });

    it('should identify default admin in wp-users.php', () => {
      const content = [
        "$user = new stdClass();",
        "$user->ID = '1';",
        "$user->user_login = 'admin';",
        "$user->user_email = 'admin@mysite.com';",
        "$user->display_name = 'Admin';",
        "$user->roles = 'administrator';",
      ].join('\n');
      fs.writeFileSync(path.join(tempDir, 'wp-users.php'), content);

      const result = checkUsers(tempDir);

      expect(result.hasIssues).toBe(true);
      expect(result.bySeverity['HIGH']).toBeGreaterThanOrEqual(1);
      const defaultAdminIssue = result.issues.find((i) => i.type === 'default_admin');
      expect(defaultAdminIssue).toBeDefined();
    });

    it('should identify default email in SQL export', () => {
      const content = [
        "INSERT INTO `wp_users` (`id`, `user_login`, `user_email`, `display_name`) VALUES (1, 'mysite_admin', 'admin@example.com', 'Admin');",
      ].join('\n');
      fs.writeFileSync(path.join(tempDir, 'users-backup.sql'), content);

      const result = checkUsers(tempDir);

      expect(result.hasIssues).toBe(true);
      const emailIssue = result.issues.find((i) => i.type === 'admin_default_email');
      expect(emailIssue).toBeDefined();
      expect(emailIssue?.severity).toBe('HIGH');
    });

    it('should count bySeverity correctly', () => {
      const content = [
        "$user = new stdClass();",
        "$user->ID = '1';",
        "$user->user_login = 'admin';",
        "$user->user_email = 'admin@example.com';",
        "$user->display_name = 'Admin';",
        "$user->roles = 'administrator';",
      ].join('\n');
      fs.writeFileSync(path.join(tempDir, 'wp-users.php'), content);

      const result = checkUsers(tempDir);

      expect(result.bySeverity['HIGH']).toBeGreaterThanOrEqual(2);
    });

    it('should return no issues for clean users', () => {
      const content = [
        "$user = new stdClass();",
        "$user->ID = '1';",
        "$user->user_login = 'john_smith';",
        "$user->user_email = 'john@realsite.com';",
        "$user->display_name = 'John Smith';",
        "$user->roles = 'administrator';",
        "",
        "$user2 = new stdClass();",
        "$user2->ID = '2';",
        "$user2->user_login = 'jane_editor';",
        "$user2->user_email = 'jane@realsite.com';",
        "$user2->display_name = 'Jane';",
        "$user2->roles = 'editor';",
      ].join('\n');
      fs.writeFileSync(path.join(tempDir, 'wp-users.php'), content);

      const result = checkUsers(tempDir);

      expect(result.usersFound).toBe(true);
      expect(result.hasIssues).toBe(false);
      expect(result.bySeverity['HIGH']).toBeUndefined();
    });

    it('should handle unreadable file gracefully', () => {
      const dirPath = path.join(tempDir, 'wp-users.php');
      fs.mkdirSync(dirPath);

      const result = checkUsers(tempDir);

      expect(result.usersFound).toBe(false);
      expect(result.source).toBe('none');
    });
  });

  describe('JSON output', () => {
    it('should produce valid JSON with --json flag', async () => {
      createWordPressInstall(tempDir);
      const content = [
        "$user = new stdClass();",
        "$user->ID = '1';",
        "$user->user_login = 'admin';",
        "$user->user_email = 'admin@site.com';",
        "$user->display_name = 'Admin';",
        "$user->roles = 'administrator';",
      ].join('\n');
      fs.writeFileSync(path.join(tempDir, 'wp-users.php'), content);

      const program = createProgram();
      registerUsersCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'users:check',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);

      expect(result).toHaveProperty('path');
      expect(result).toHaveProperty('usersFound');
      expect(result).toHaveProperty('source');
      expect(result).toHaveProperty('users');
      expect(result).toHaveProperty('issues');
      expect(result).toHaveProperty('hasIssues');
      expect(result).toHaveProperty('bySeverity');
      mockExit.mockRestore();
    });

    it('should produce valid JSON for error case', async () => {
      const program = createProgram();
      registerUsersCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'users:check',
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

    it('should produce valid JSON when no users found', async () => {
      createWordPressInstall(tempDir);
      const program = createProgram();
      registerUsersCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'users:check',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);

      expect(result.usersFound).toBe(false);
      expect(result.users).toHaveLength(0);
      expect(result.hasIssues).toBe(false);
      mockExit.mockRestore();
    });
  });

  describe('human-readable output', () => {
    it('should print check info without --json', async () => {
      createWordPressInstall(tempDir);
      const content = [
        "$user = new stdClass();",
        "$user->ID = '1';",
        "$user->user_login = 'admin';",
        "$user->user_email = 'admin@site.com';",
        "$user->display_name = 'Admin';",
        "$user->roles = 'administrator';",
      ].join('\n');
      fs.writeFileSync(path.join(tempDir, 'wp-users.php'), content);

      const program = createProgram();
      registerUsersCheckCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'users:check',
          '--path', tempDir,
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const allOutput = consoleSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('Checking WordPress admin users');
      expect(allOutput).toContain('WordPress Users');
      expect(allOutput).toContain('Security Issues');
      mockExit.mockRestore();
    });

    it('should warn when no user data found', async () => {
      createWordPressInstall(tempDir);
      const program = createProgram();
      registerUsersCheckCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'users:check',
          '--path', tempDir,
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      expect(consoleWarnSpy).toHaveBeenCalledWith(
        expect.stringContaining('No WordPress user data found')
      );
      mockExit.mockRestore();
    });

    it('should display issues with severity tags', async () => {
      createWordPressInstall(tempDir);
      const content = [
        "$user = new stdClass();",
        "$user->ID = '1';",
        "$user->user_login = 'admin';",
        "$user->user_email = 'admin@example.com';",
        "$user->display_name = 'Admin';",
        "$user->roles = 'administrator';",
      ].join('\n');
      fs.writeFileSync(path.join(tempDir, 'wp-users.php'), content);

      const program = createProgram();
      registerUsersCheckCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'users:check',
          '--path', tempDir,
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      const allOutput = consoleSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('[HIGH]');
      expect(allOutput).toContain('default admin');
      mockExit.mockRestore();
    });
  });

  describe('exit codes', () => {
    it('should exit 1 when high severity issues found', async () => {
      createWordPressInstall(tempDir);
      const content = [
        "$user = new stdClass();",
        "$user->ID = '1';",
        "$user->user_login = 'admin';",
        "$user->user_email = 'admin@example.com';",
        "$user->display_name = 'Admin';",
        "$user->roles = 'administrator';",
      ].join('\n');
      fs.writeFileSync(path.join(tempDir, 'wp-users.php'), content);

      const program = createProgram();
      registerUsersCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'users:check',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      expect(mockExit).toHaveBeenCalledWith(1);
      mockExit.mockRestore();
    });

    it('should exit 0 when no high severity issues', async () => {
      createWordPressInstall(tempDir);
      const content = [
        "$user = new stdClass();",
        "$user->ID = '1';",
        "$user->user_login = 'john_smith';",
        "$user->user_email = 'john@realsite.com';",
        "$user->display_name = 'John Smith';",
        "$user->roles = 'administrator';",
      ].join('\n');
      fs.writeFileSync(path.join(tempDir, 'wp-users.php'), content);

      const program = createProgram();
      registerUsersCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'users:check',
          '--path', tempDir,
          '--json',
        ]);
      } catch {
        // exitOverride + process.exit mock may throw
      }

      expect(mockExit).toHaveBeenCalledWith(0);
      mockExit.mockRestore();
    });

    it('should exit 0 when no users found', async () => {
      createWordPressInstall(tempDir);
      const program = createProgram();
      registerUsersCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync([
          'node', 'test', 'users:check',
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
