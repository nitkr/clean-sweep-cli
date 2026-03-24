import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  generateEmailBody,
  generateDefaultSubject,
  generateEmailScript,
  generateSendmailScript,
  generateCurlOnlyScript,
  getDefaultScriptPath,
  saveEmailScript,
  SmtpConfig,
  EmailNotificationData,
} from '../src/email-notification';
import { ScanResult, Threat } from '../src/malware-scanner';
import { Vulnerability } from '../src/vulnerability-scanner';
import { IntegrityResult } from '../src/file-integrity';

function createMockScanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    path: '/test/path',
    files: ['/test/path/file.php'],
    directories: ['/test/path/subdir'],
    totalFiles: 10,
    totalDirectories: 2,
    threats: [],
    safe: true,
    dryRun: false,
    whitelisted: 0,
    ...overrides,
  };
}

function createMockThreat(overrides: Partial<Threat> = {}): Threat {
  return {
    file: '/test/path/malicious.php',
    type: 'php_eval',
    line: 5,
    signature: 'eval(',
    ...overrides,
  };
}

function createMockConfig(): SmtpConfig {
  return {
    host: 'smtp.example.com',
    port: 587,
    user: 'user@example.com',
    pass: 'secretpass',
    from: 'scanner@example.com',
    to: 'admin@example.com',
  };
}

describe('Email Notification Module', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'email-notif-test-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('generateEmailBody', () => {
    it('should return a plain text string', () => {
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
      };
      const body = generateEmailBody(data);
      expect(typeof body).toBe('string');
      expect(body.length).toBeGreaterThan(0);
    });

    it('should include the scan path', () => {
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/var/www/wordpress',
        scanResult: createMockScanResult(),
      };
      const body = generateEmailBody(data);
      expect(body).toContain('/var/www/wordpress');
    });

    it('should include the timestamp', () => {
      const data: EmailNotificationData = {
        timestamp: '2024-01-15T10:30:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
      };
      const body = generateEmailBody(data);
      expect(body).toContain('2024-01-15T10:30:00.000Z');
    });

    it('should display CLEAN status when no threats found', () => {
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ safe: true, threats: [] }),
      };
      const body = generateEmailBody(data);
      expect(body).toContain('CLEAN');
    });

    it('should display THREATS DETECTED status when threats found', () => {
      const threat = createMockThreat();
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ safe: false, threats: [threat] }),
      };
      const body = generateEmailBody(data);
      expect(body).toContain('THREATS DETECTED');
    });

    it('should list threat details', () => {
      const threats: Threat[] = [
        createMockThreat({ file: '/test/backdoor.php', type: 'php_eval', line: 10, signature: 'eval(' }),
        createMockThreat({ file: '/test/shell.php', type: 'php_shell_exec', line: null, signature: 'shell_exec(' }),
      ];
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ safe: false, threats }),
      };
      const body = generateEmailBody(data);
      expect(body).toContain('/test/backdoor.php');
      expect(body).toContain('/test/shell.php');
      expect(body).toContain('php_eval');
      expect(body).toContain('php_shell_exec');
    });

    it('should display line numbers when available', () => {
      const threat = createMockThreat({ line: 42 });
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ safe: false, threats: [threat] }),
      };
      const body = generateEmailBody(data);
      expect(body).toContain(':42');
    });

    it('should not display line number when null', () => {
      const threat = createMockThreat({ line: null });
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ safe: false, threats: [threat] }),
      };
      const body = generateEmailBody(data);
      expect(body).not.toMatch(/:null/);
    });

    it('should display file count in summary', () => {
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ totalFiles: 42 }),
      };
      const body = generateEmailBody(data);
      expect(body).toContain('42');
    });

    it('should display vulnerabilities when provided', () => {
      const vulnerabilities: Vulnerability[] = [
        {
          component: 'wordpress',
          version: '6.0',
          cve: 'CVE-2024-1234',
          title: 'SQL Injection',
          severity: 'high',
        },
      ];
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
        vulnerabilities,
      };
      const body = generateEmailBody(data);
      expect(body).toContain('Known Vulnerabilities');
      expect(body).toContain('wordpress');
      expect(body).toContain('CVE-2024-1234');
      expect(body).toContain('SQL Injection');
    });

    it('should not include vulnerabilities section when empty', () => {
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
        vulnerabilities: [],
      };
      const body = generateEmailBody(data);
      expect(body).not.toContain('Known Vulnerabilities');
    });

    it('should display integrity results when provided', () => {
      const integrity: IntegrityResult = {
        checked: 100,
        modified: 2,
        modifiedFiles: ['wp-login.php', 'wp-config.php'],
        wordpressVersion: '6.3',
      };
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
        integrity,
      };
      const body = generateEmailBody(data);
      expect(body).toContain('File Integrity');
      expect(body).toContain('6.3');
      expect(body).toContain('wp-login.php');
      expect(body).toContain('wp-config.php');
    });

    it('should not include integrity section when not provided', () => {
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
      };
      const body = generateEmailBody(data);
      expect(body).not.toContain('Modified Files');
    });

    it('should include footer', () => {
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
      };
      const body = generateEmailBody(data);
      expect(body).toContain('Clean Sweep CLI');
    });
  });

  describe('generateDefaultSubject', () => {
    it('should include CLEAN for safe scans', () => {
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ safe: true, threats: [] }),
      };
      const subject = generateDefaultSubject(data);
      expect(subject).toContain('CLEAN');
    });

    it('should include THREATS DETECTED for unsafe scans', () => {
      const threat = createMockThreat();
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ safe: false, threats: [threat] }),
      };
      const subject = generateDefaultSubject(data);
      expect(subject).toContain('THREATS DETECTED');
    });

    it('should include the scan path', () => {
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/var/www/html',
        scanResult: createMockScanResult(),
      };
      const subject = generateDefaultSubject(data);
      expect(subject).toContain('/var/www/html');
    });

    it('should include threat count', () => {
      const threats = [createMockThreat(), createMockThreat({ file: '/test/b.php' })];
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ safe: false, threats }),
      };
      const subject = generateDefaultSubject(data);
      expect(subject).toContain('2 threats');
    });

    it('should use singular "threat" for single threat', () => {
      const threats = [createMockThreat()];
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ safe: false, threats }),
      };
      const subject = generateDefaultSubject(data);
      expect(subject).toContain('1 threat)');
      expect(subject).not.toContain('1 threats');
    });

    it('should include [Clean Sweep] prefix', () => {
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
      };
      const subject = generateDefaultSubject(data);
      expect(subject.startsWith('[Clean Sweep]')).toBe(true);
    });
  });

  describe('generateSendmailScript', () => {
    it('should generate a bash script', () => {
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
      };
      const script = generateSendmailScript(data, createMockConfig());
      expect(script).toContain('#!/usr/bin/env bash');
    });

    it('should include SMTP configuration from config', () => {
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
      };
      const config = createMockConfig();
      const script = generateSendmailScript(data, config);
      expect(script).toContain('smtp.example.com');
      expect(script).toContain('587');
      expect(script).toContain('user@example.com');
      expect(script).toContain('scanner@example.com');
      expect(script).toContain('admin@example.com');
    });

    it('should include set -euo pipefail for safety', () => {
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
      };
      const script = generateSendmailScript(data, createMockConfig());
      expect(script).toContain('set -euo pipefail');
    });

    it('should detect multiple mail utilities', () => {
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
      };
      const script = generateSendmailScript(data, createMockConfig());
      expect(script).toContain('curl');
      expect(script).toContain('sendmail');
      expect(script).toContain('mail');
    });

    it('should include the email body', () => {
      const threat = createMockThreat();
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult({ safe: false, threats: [threat] }),
      };
      const script = generateSendmailScript(data, createMockConfig());
      expect(script).toContain('THREATS DETECTED');
      expect(script).toContain('/test/path/malicious.php');
    });

    it('should include custom subject when provided', () => {
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
        subject: 'Custom Alert Subject',
      };
      const script = generateSendmailScript(data, createMockConfig());
      expect(script).toContain('Custom Alert Subject');
    });

    it('should escape single quotes in config values', () => {
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: "/test/it's a path",
        scanResult: createMockScanResult(),
      };
      const config: SmtpConfig = {
        host: "smtp.o'connor.com",
        port: 587,
        user: "user's@example.com",
        pass: "pass'word",
        from: "scan's@example.com",
        to: "admin's@example.com",
      };
      const script = generateSendmailScript(data, config);
      expect(script).toContain("\\'");
    });
  });

  describe('generateCurlOnlyScript', () => {
    it('should generate a bash script', () => {
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
      };
      const script = generateCurlOnlyScript(data, createMockConfig());
      expect(script).toContain('#!/usr/bin/env bash');
    });

    it('should only reference curl, not sendmail or mail', () => {
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
      };
      const script = generateCurlOnlyScript(data, createMockConfig());
      expect(script).toContain('curl');
      expect(script).toContain('command -v curl');
      expect(script).not.toContain('sendmail');
    });

    it('should use environment variable defaults', () => {
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
      };
      const script = generateCurlOnlyScript(data, createMockConfig());
      expect(script).toContain('SMTP_HOST=${SMTP_HOST:-');
      expect(script).toContain('SMTP_PORT=${SMTP_PORT:-');
    });

    it('should include smtp curl command', () => {
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
      };
      const script = generateCurlOnlyScript(data, createMockConfig());
      expect(script).toContain('--url "smtp://');
      expect(script).toContain('--ssl-reqd');
      expect(script).toContain('--mail-from');
      expect(script).toContain('--mail-rcpt');
      expect(script).toContain('--upload-file');
    });
  });

  describe('generateEmailScript', () => {
    it('should return auto script by default', () => {
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
      };
      const script = generateEmailScript(data, createMockConfig());
      expect(script).toContain('MAILER=');
    });

    it('should return auto script when mode is auto', () => {
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
      };
      const script = generateEmailScript(data, createMockConfig(), 'auto');
      expect(script).toContain('MAILER=');
    });

    it('should return curl-only script when mode is curl', () => {
      const data: EmailNotificationData = {
        timestamp: '2024-01-01T00:00:00.000Z',
        scanPath: '/test/path',
        scanResult: createMockScanResult(),
      };
      const script = generateEmailScript(data, createMockConfig(), 'curl');
      expect(script).toContain('command -v curl');
      expect(script).not.toContain('MAILER=');
    });

    it('should use env config when no config provided', () => {
      const origEnv = { ...process.env };
      process.env.SMTP_HOST = 'mail.test.com';
      process.env.SMTP_PORT = '465';
      process.env.SMTP_USER = 'envuser@test.com';
      process.env.SMTP_PASS = 'envpass';
      process.env.SMTP_FROM = 'envfrom@test.com';
      process.env.SMTP_TO = 'envto@test.com';

      try {
        const data: EmailNotificationData = {
          timestamp: '2024-01-01T00:00:00.000Z',
          scanPath: '/test/path',
          scanResult: createMockScanResult(),
        };
        const script = generateEmailScript(data);
        expect(script).toContain('mail.test.com');
        expect(script).toContain('465');
        expect(script).toContain('envuser@test.com');
      } finally {
        process.env = origEnv;
      }
    });
  });

  describe('getDefaultScriptPath', () => {
    it('should return a valid path string', () => {
      const scriptPath = getDefaultScriptPath('/test/path');
      expect(typeof scriptPath).toBe('string');
      expect(scriptPath.length).toBeGreaterThan(0);
    });

    it('should include reports directory', () => {
      const scriptPath = getDefaultScriptPath('/test/path');
      expect(scriptPath.startsWith(path.join('clean-sweep-cli', 'reports'))).toBe(true);
    });

    it('should include .sh extension', () => {
      const scriptPath = getDefaultScriptPath('/test/path');
      expect(scriptPath.endsWith('.sh')).toBe(true);
    });

    it('should include email prefix', () => {
      const scriptPath = getDefaultScriptPath('/test/path');
      expect(scriptPath.includes('email-')).toBe(true);
    });

    it('should include timestamp in the path', () => {
      const scriptPath = getDefaultScriptPath('/test/path');
      const hasTimestamp = scriptPath.match(/\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}/);
      expect(hasTimestamp).not.toBeNull();
    });

    it('should handle special characters in scanPath', () => {
      const scriptPath = getDefaultScriptPath('/test/path with spaces!');
      expect(scriptPath).toBeDefined();
      expect(scriptPath.endsWith('.sh')).toBe(true);
    });

    it('should handle empty scanPath', () => {
      const scriptPath = getDefaultScriptPath('');
      expect(scriptPath).toBeDefined();
      expect(scriptPath.startsWith(path.join('clean-sweep-cli', 'reports') + path.sep)).toBe(true);
    });

    it('should produce unique paths for different calls', async () => {
      const path1 = getDefaultScriptPath('/test/path');
      await new Promise(resolve => setTimeout(resolve, 10));
      const path2 = getDefaultScriptPath('/test/path');
      expect(path1).not.toBe(path2);
    });
  });

  describe('saveEmailScript', () => {
    it('should create the script file', () => {
      const script = '#!/bin/bash\necho "test"';
      const filePath = path.join(tempDir, 'test-script.sh');
      saveEmailScript(script, filePath);
      expect(fs.existsSync(filePath)).toBe(true);
    });

    it('should save correct script content', () => {
      const script = '#!/bin/bash\necho "hello world"';
      const filePath = path.join(tempDir, 'test-script.sh');
      saveEmailScript(script, filePath);
      const content = fs.readFileSync(filePath, 'utf-8');
      expect(content).toBe(script);
    });

    it('should create nested directories if needed', () => {
      const script = '#!/bin/bash\necho "test"';
      const filePath = path.join(tempDir, 'nested', 'dir', 'script.sh');
      saveEmailScript(script, filePath);
      expect(fs.existsSync(filePath)).toBe(true);
    });

    it('should set executable permissions', () => {
      const script = '#!/bin/bash\necho "test"';
      const filePath = path.join(tempDir, 'test-script.sh');
      saveEmailScript(script, filePath);
      const stats = fs.statSync(filePath);
      expect(stats.mode & 0o111).toBeTruthy();
    });

    it('should overwrite existing file', () => {
      const script1 = '#!/bin/bash\necho "first"';
      const script2 = '#!/bin/bash\necho "second"';
      const filePath = path.join(tempDir, 'test-script.sh');

      saveEmailScript(script1, filePath);
      saveEmailScript(script2, filePath);

      const content = fs.readFileSync(filePath, 'utf-8');
      expect(content).toBe(script2);
    });

    it('should handle unicode in script content', () => {
      const script = '#!/bin/bash\necho "日本語 テスト"';
      const filePath = path.join(tempDir, 'unicode-script.sh');
      saveEmailScript(script, filePath);
      const content = fs.readFileSync(filePath, 'utf-8');
      expect(content).toContain('日本語');
    });
  });

  describe('Full integration: generate and save script', () => {
    it('should generate and save a complete notification script', () => {
      const threats: Threat[] = [
        createMockThreat({ file: '/test/backdoor.php', type: 'php_eval', line: 10, signature: 'eval(base64_decode(' }),
        createMockThreat({ file: '/test/shell.php', type: 'php_shell_exec', line: null, signature: 'shell_exec(' }),
      ];

      const vulnerabilities: Vulnerability[] = [
        { component: 'wordpress', version: '6.0', cve: 'CVE-2024-0001', title: 'XSS Vulnerability', severity: 'medium' },
      ];

      const integrity: IntegrityResult = {
        checked: 50,
        modified: 1,
        modifiedFiles: ['wp-login.php'],
        wordpressVersion: '6.0',
      };

      const data: EmailNotificationData = {
        timestamp: '2024-01-15T10:30:00.000Z',
        scanPath: '/var/www/html',
        scanResult: createMockScanResult({ safe: false, threats, totalFiles: 50 }),
        vulnerabilities,
        integrity,
      };

      const config = createMockConfig();
      const script = generateEmailScript(data, config);
      const filePath = path.join(tempDir, 'reports', 'notification.sh');
      saveEmailScript(script, filePath);

      expect(fs.existsSync(filePath)).toBe(true);
      const content = fs.readFileSync(filePath, 'utf-8');

      expect(content).toContain('#!/usr/bin/env bash');
      expect(content).toContain('smtp.example.com');
      expect(content).toContain('/var/www/html');
      expect(content).toContain('THREATS DETECTED');
      expect(content).toContain('/test/backdoor.php');
      expect(content).toContain('/test/shell.php');
      expect(content).toContain('Known Vulnerabilities');
      expect(content).toContain('CVE-2024-0001');
      expect(content).toContain('File Integrity');
      expect(content).toContain('wp-login.php');
    });

    it('should generate and save a curl-only script', () => {
      const data: EmailNotificationData = {
        timestamp: '2024-01-15T10:30:00.000Z',
        scanPath: '/clean/site',
        scanResult: createMockScanResult({ safe: true, threats: [], totalFiles: 25 }),
      };

      const config = createMockConfig();
      const script = generateEmailScript(data, config, 'curl');
      const filePath = path.join(tempDir, 'curl-notification.sh');
      saveEmailScript(script, filePath);

      expect(fs.existsSync(filePath)).toBe(true);
      const content = fs.readFileSync(filePath, 'utf-8');

      expect(content).toContain('CLEAN');
      expect(content).toContain('command -v curl');
      expect(content).not.toContain('MAILER=');
    });
  });
});
