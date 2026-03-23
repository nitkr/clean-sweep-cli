import { describe, it, expect } from '@jest/globals';
import {
  generateChmodCommands,
  generateRmCommands,
  generateBackupCommands,
  generateRemediationScript,
  PermissionIssueInput,
  ThreatInput,
} from '../src/shell-remediation';

describe('Shell Remediation Module', () => {
  describe('generateChmodCommands', () => {
    it('should generate chmod commands for permission issues', () => {
      const issues: PermissionIssueInput[] = [
        { file: '/var/www/html/wp-config.php', suggestedMode: '0600', type: 'world_readable_sensitive' },
        { file: '/var/www/html/uploads', suggestedMode: '0755', type: 'directory_world_writable' },
      ];

      const commands = generateChmodCommands(issues);

      expect(commands).toHaveLength(2);
      expect(commands[0].command).toBe('chmod 0600 "/var/www/html/wp-config.php"');
      expect(commands[0].file).toBe('/var/www/html/wp-config.php');
      expect(commands[0].mode).toBe('0600');
      expect(commands[0].issueType).toBe('world_readable_sensitive');
      expect(commands[1].command).toBe('chmod 0755 "/var/www/html/uploads"');
    });

    it('should return empty array for no issues', () => {
      const commands = generateChmodCommands([]);

      expect(commands).toHaveLength(0);
    });

    it('should handle world-writable file', () => {
      const issues: PermissionIssueInput[] = [
        { file: '/var/www/html/script.js', suggestedMode: '0644', type: 'world_writable' },
      ];

      const commands = generateChmodCommands(issues);

      expect(commands[0].command).toBe('chmod 0644 "/var/www/html/script.js"');
      expect(commands[0].issueType).toBe('world_writable');
    });

    it('should handle setuid/setgid removal', () => {
      const issues: PermissionIssueInput[] = [
        { file: '/usr/local/bin/suspicious', suggestedMode: '0755', type: 'setuid_setgid' },
      ];

      const commands = generateChmodCommands(issues);

      expect(commands[0].command).toBe('chmod 0755 "/usr/local/bin/suspicious"');
      expect(commands[0].mode).toBe('0755');
    });

    it('should handle unexpected executable', () => {
      const issues: PermissionIssueInput[] = [
        { file: '/var/www/html/index.ts', suggestedMode: '0644', type: 'unexpected_executable' },
      ];

      const commands = generateChmodCommands(issues);

      expect(commands[0].command).toBe('chmod 0644 "/var/www/html/index.ts"');
    });

    it('should handle multiple issues with different modes', () => {
      const issues: PermissionIssueInput[] = [
        { file: '/a/b/file1.txt', suggestedMode: '0644', type: 'world_writable' },
        { file: '/a/b/file2.txt', suggestedMode: '0600', type: 'world_readable_sensitive' },
        { file: '/a/b/file3.txt', suggestedMode: '0755', type: 'setuid_setgid' },
      ];

      const commands = generateChmodCommands(issues);

      expect(commands).toHaveLength(3);
      expect(commands.map((c) => c.mode)).toEqual(['0644', '0600', '0755']);
    });
  });

  describe('generateRmCommands', () => {
    it('should generate rm commands for threats', () => {
      const threats: ThreatInput[] = [
        { file: '/var/www/html/malicious.php', signature: 'eval(base64_decode(...))', type: 'php_eval' },
        { file: '/var/www/html/backdoor.php', signature: 'shell_exec(...)', type: 'php_shell_exec' },
      ];

      const commands = generateRmCommands(threats);

      expect(commands).toHaveLength(2);
      expect(commands[0].command).toBe('rm -f "/var/www/html/malicious.php"');
      expect(commands[0].file).toBe('/var/www/html/malicious.php');
      expect(commands[0].threatType).toBe('php_eval');
      expect(commands[0].signature).toBe('eval(base64_decode(...))');
      expect(commands[1].command).toBe('rm -f "/var/www/html/backdoor.php"');
    });

    it('should return empty array for no threats', () => {
      const commands = generateRmCommands([]);

      expect(commands).toHaveLength(0);
    });

    it('should handle single threat', () => {
      const threats: ThreatInput[] = [
        { file: '/tmp/shell.php', signature: 'passthru(...)', type: 'php_passthru' },
      ];

      const commands = generateRmCommands(threats);

      expect(commands).toHaveLength(1);
      expect(commands[0].command).toBe('rm -f "/tmp/shell.php"');
      expect(commands[0].threatType).toBe('php_passthru');
    });

    it('should handle file paths with spaces', () => {
      const threats: ThreatInput[] = [
        { file: '/var/www/html/my file.php', signature: 'eval(...)', type: 'php_eval' },
      ];

      const commands = generateRmCommands(threats);

      expect(commands[0].command).toBe('rm -f "/var/www/html/my file.php"');
    });

    it('should handle different threat types', () => {
      const threats: ThreatInput[] = [
        { file: '/a.php', signature: 'eval(...)', type: 'php_eval' },
        { file: '/b.js', signature: 'eval("...")', type: 'js_eval_dynamic' },
        { file: '/c.php', signature: 'AAAA...', type: 'base64_large' },
      ];

      const commands = generateRmCommands(threats);

      expect(commands.map((c) => c.threatType)).toEqual(['php_eval', 'js_eval_dynamic', 'base64_large']);
    });
  });

  describe('generateBackupCommands', () => {
    it('should generate mkdir and cp commands', () => {
      const files = ['/var/www/html/malicious.php', '/var/www/html/config.php'];
      const backupDir = '/tmp/clean-sweep-backup-2024-01-01';

      const commands = generateBackupCommands(files, backupDir);

      expect(commands).toHaveLength(3);
      expect(commands[0].command).toBe('mkdir -p "/tmp/clean-sweep-backup-2024-01-01"');
      expect(commands[0].source).toBe('');
      expect(commands[1].command).toBe('cp -p "/var/www/html/malicious.php" "/tmp/clean-sweep-backup-2024-01-01/malicious.php"');
      expect(commands[1].source).toBe('/var/www/html/malicious.php');
      expect(commands[2].command).toBe('cp -p "/var/www/html/config.php" "/tmp/clean-sweep-backup-2024-01-01/config.php"');
    });

    it('should return only mkdir command for empty file list', () => {
      const commands = generateBackupCommands([], '/tmp/backup');

      expect(commands).toHaveLength(1);
      expect(commands[0].command).toBe('mkdir -p "/tmp/backup"');
    });

    it('should preserve file basename in backup destination', () => {
      const files = ['/var/www/html/subdir/deep/file.php'];
      const backupDir = '/tmp/backup';

      const commands = generateBackupCommands(files, backupDir);

      expect(commands[1].command).toBe('cp -p "/var/www/html/subdir/deep/file.php" "/tmp/backup/file.php"');
      expect(commands[1].destination).toBe('/tmp/backup/file.php');
    });

    it('should handle multiple files in the same directory', () => {
      const files = [
        '/var/www/html/a.php',
        '/var/www/html/b.php',
        '/var/www/html/c.php',
      ];
      const backupDir = '/tmp/backup';

      const commands = generateBackupCommands(files, backupDir);

      expect(commands).toHaveLength(4);
      expect(commands.filter((c) => c.command.startsWith('cp'))).toHaveLength(3);
    });

    it('should handle files with special characters in names', () => {
      const files = ['/var/www/html/file with spaces.php'];
      const backupDir = '/tmp/backup';

      const commands = generateBackupCommands(files, backupDir);

      expect(commands[1].command).toBe('cp -p "/var/www/html/file with spaces.php" "/tmp/backup/file with spaces.php"');
    });
  });

  describe('generateRemediationScript', () => {
    const permissionIssues: PermissionIssueInput[] = [
      { file: '/var/www/html/wp-config.php', suggestedMode: '0600', type: 'world_readable_sensitive' },
      { file: '/var/www/html/uploads', suggestedMode: '0755', type: 'directory_world_writable' },
    ];

    const threats: ThreatInput[] = [
      { file: '/var/www/html/malicious.php', signature: 'eval(base64_decode(...))', type: 'php_eval' },
      { file: '/var/www/html/backdoor.js', signature: 'Function("...")', type: 'js_function_dynamic' },
    ];

    it('should generate a valid bash script', () => {
      const script = generateRemediationScript(permissionIssues, threats, '/tmp/backup-2024');

      expect(script.fullScript).toContain('#!/usr/bin/env bash');
      expect(script.fullScript).toContain('set -euo pipefail');
      expect(script.fullScript).toContain('echo "Remediation complete."');
    });

    it('should include backup commands for all affected files', () => {
      const script = generateRemediationScript(permissionIssues, threats, '/tmp/backup');

      expect(script.backupSection.join('\n')).toContain('mkdir -p "/tmp/backup"');
      expect(script.backupSection.join('\n')).toContain('wp-config.php');
      expect(script.backupSection.join('\n')).toContain('malicious.php');
      expect(script.backupSection.join('\n')).toContain('backdoor.js');
    });

    it('should include chmod commands in permission fix section', () => {
      const script = generateRemediationScript(permissionIssues, threats, '/tmp/backup');

      const permSection = script.permissionFixSection.join('\n');
      expect(permSection).toContain('chmod 0600 "/var/www/html/wp-config.php"');
      expect(permSection).toContain('chmod 0755 "/var/www/html/uploads"');
    });

    it('should include rm commands in removal section', () => {
      const script = generateRemediationScript(permissionIssues, threats, '/tmp/backup');

      const rmSection = script.removalSection.join('\n');
      expect(rmSection).toContain('rm -f "/var/www/html/malicious.php"');
      expect(rmSection).toContain('rm -f "/var/www/html/backdoor.js"');
    });

    it('should order sections correctly: backup, permissions, removal', () => {
      const script = generateRemediationScript(permissionIssues, threats, '/tmp/backup');

      const fullScript = script.fullScript;
      const backupPos = fullScript.indexOf('Step 1: Backup');
      const permPos = fullScript.indexOf('Step 2: Fix file permissions');
      const removalPos = fullScript.indexOf('Step 3: Remove malware');

      expect(backupPos).toBeLessThan(permPos);
      expect(permPos).toBeLessThan(removalPos);
    });

    it('should handle empty permission issues', () => {
      const script = generateRemediationScript([], threats, '/tmp/backup');

      const permSection = script.permissionFixSection.join('\n');
      expect(permSection).not.toContain('chmod');
      expect(script.removalSection.join('\n')).toContain('rm -f');
    });

    it('should handle empty threats', () => {
      const script = generateRemediationScript(permissionIssues, [], '/tmp/backup');

      const rmSection = script.removalSection.join('\n');
      expect(rmSection).not.toContain('rm -f');
      expect(script.permissionFixSection.join('\n')).toContain('chmod');
    });

    it('should handle both empty inputs', () => {
      const script = generateRemediationScript([], [], '/tmp/backup');

      expect(script.fullScript).toContain('#!/usr/bin/env bash');
      expect(script.fullScript).toContain('Remediation complete.');
      expect(script.backupSection.join('\n')).toContain('mkdir -p');
    });

    it('should deduplicate files in backup section', () => {
      const issues: PermissionIssueInput[] = [
        { file: '/var/www/html/same.php', suggestedMode: '0644', type: 'world_writable' },
      ];
      const threatsInput: ThreatInput[] = [
        { file: '/var/www/html/same.php', signature: 'eval(...)', type: 'php_eval' },
      ];

      const script = generateRemediationScript(issues, threatsInput, '/tmp/backup');

      const backupText = script.backupSection.join('\n');
      const cpMatches = backupText.match(/cp -p/g) || [];
      expect(cpMatches).toHaveLength(1);
    });

    it('should include generated timestamp in header', () => {
      const script = generateRemediationScript([], [], '/tmp/backup');

      expect(script.header).toContain('# Generated:');
    });

    it('should include warning comment in header', () => {
      const script = generateRemediationScript([], [], '/tmp/backup');

      expect(script.header).toContain('WARNING');
      expect(script.header).toContain('Review this script carefully');
    });

    it('should include echo progress messages', () => {
      const script = generateRemediationScript(permissionIssues, threats, '/tmp/backup');

      expect(script.fullScript).toContain('echo "Creating backups..."');
      expect(script.fullScript).toContain('echo "Backup complete."');
      expect(script.fullScript).toContain('echo "Fixing permissions..."');
      expect(script.fullScript).toContain('echo "Permission fixes applied."');
      expect(script.fullScript).toContain('echo "Removing infected files..."');
      expect(script.fullScript).toContain('echo "Removal complete."');
    });

    it('should export separate section strings for flexible use', () => {
      const script = generateRemediationScript(permissionIssues, threats, '/tmp/backup');

      expect(script.header).toBeDefined();
      expect(script.backupSection).toBeInstanceOf(Array);
      expect(script.permissionFixSection).toBeInstanceOf(Array);
      expect(script.removalSection).toBeInstanceOf(Array);
      expect(typeof script.fullScript).toBe('string');
    });

    it('should handle file paths with special characters', () => {
      const issues: PermissionIssueInput[] = [
        { file: "/var/www/html/file's name.php", suggestedMode: '0600', type: 'world_readable_sensitive' },
      ];

      const script = generateRemediationScript(issues, [], '/tmp/backup');

      expect(script.permissionFixSection.join('\n')).toContain("file's name.php");
    });
  });
});
