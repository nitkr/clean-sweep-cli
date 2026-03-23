import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  getCronExpression,
  getFrequencyDescription,
  buildCronConfig,
  buildCronLine,
  generateShellScript,
  writeShellScript,
} from '../src/commands/schedule';

describe('Schedule Module', () => {
  describe('getCronExpression', () => {
    it('should return correct expression for daily', () => {
      expect(getCronExpression('daily')).toBe('0 2 * * *');
    });

    it('should return correct expression for weekly', () => {
      expect(getCronExpression('weekly')).toBe('0 3 * * 0');
    });

    it('should return correct expression for monthly', () => {
      expect(getCronExpression('monthly')).toBe('0 4 1 * *');
    });
  });

  describe('getFrequencyDescription', () => {
    it('should return correct description for daily', () => {
      expect(getFrequencyDescription('daily')).toBe('Every day at 2:00 AM');
    });

    it('should return correct description for weekly', () => {
      expect(getFrequencyDescription('weekly')).toBe('Every Sunday at 3:00 AM');
    });

    it('should return correct description for monthly', () => {
      expect(getFrequencyDescription('monthly')).toBe('1st of each month at 4:00 AM');
    });
  });

  describe('buildCronConfig', () => {
    it('should build config with correct fields for daily', () => {
      const config = buildCronConfig('daily', '/var/www/html', '/scripts/clean-sweep-daily.sh');

      expect(config.expression).toBe('0 2 * * *');
      expect(config.command).toBe('/bin/bash /scripts/clean-sweep-daily.sh');
      expect(config.frequency).toBe('daily');
      expect(config.description).toBe('Every day at 2:00 AM');
    });

    it('should build config with correct fields for weekly', () => {
      const config = buildCronConfig('weekly', '/var/www', '/scripts/clean-sweep-weekly.sh');

      expect(config.expression).toBe('0 3 * * 0');
      expect(config.command).toBe('/bin/bash /scripts/clean-sweep-weekly.sh');
      expect(config.frequency).toBe('weekly');
    });

    it('should build config with correct fields for monthly', () => {
      const config = buildCronConfig('monthly', '/var/www', '/scripts/clean-sweep-monthly.sh');

      expect(config.expression).toBe('0 4 1 * *');
      expect(config.command).toBe('/bin/bash /scripts/clean-sweep-monthly.sh');
      expect(config.frequency).toBe('monthly');
    });
  });

  describe('buildCronLine', () => {
    it('should produce a valid cron line', () => {
      const config = buildCronConfig('daily', '/var/www', '/scripts/clean-sweep-daily.sh');
      const line = buildCronLine(config);

      expect(line).toBe('0 2 * * * /bin/bash /scripts/clean-sweep-daily.sh');
    });

    it('should include all 5 cron fields', () => {
      const config = buildCronConfig('weekly', '/var/www', '/s.sh');
      const line = buildCronLine(config);
      const fields = line.split(' ');

      expect(fields.length).toBeGreaterThanOrEqual(5);
    });
  });

  describe('generateShellScript', () => {
    it('should produce a script with shebang line', () => {
      const script = generateShellScript('/var/www/html', '/logs');

      expect(script).toMatch(/^#!\/usr\/bin\/env bash/);
    });

    it('should set pipefail', () => {
      const script = generateShellScript('/var/www/html', '/logs');

      expect(script).toContain('set -euo pipefail');
    });

    it('should include the scan path', () => {
      const script = generateShellScript('/var/www/html', '/logs');

      expect(script).toContain("SCAN_PATH='/var/www/html'");
    });

    it('should include the log directory', () => {
      const script = generateShellScript('/var/www/html', '/var/log/clean-sweep');

      expect(script).toContain("LOG_DIR='/var/log/clean-sweep'");
    });

    it('should call clean-sweep scan with --json and --report', () => {
      const script = generateShellScript('/var/www/html', '/logs');

      expect(script).toContain('clean-sweep scan');
      expect(script).toContain('--json');
      expect(script).toContain('--report');
    });

    it('should escape single quotes in paths', () => {
      const script = generateShellScript("/var/www/it's-a-test", '/logs');

      expect(script).toContain("'/var/www/it'\\''s-a-test'");
    });

    it('should include log rotation logic', () => {
      const script = generateShellScript('/var/www/html', '/logs');

      expect(script).toContain('tail -n +31');
    });

    it('should capture exit code', () => {
      const script = generateShellScript('/var/www/html', '/logs');

      expect(script).toContain('PIPESTATUS');
      expect(script).toContain('EXIT_CODE');
    });
  });

  describe('writeShellScript', () => {
    let tempDir: string;

    beforeEach(() => {
      tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'schedule-test-'));
    });

    afterEach(() => {
      if (tempDir && fs.existsSync(tempDir)) {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });

    it('should write script to the specified path', () => {
      const scriptPath = path.join(tempDir, 'test.sh');
      const content = '#!/bin/bash\necho "hello"\n';

      writeShellScript(content, scriptPath);

      expect(fs.existsSync(scriptPath)).toBe(true);
      expect(fs.readFileSync(scriptPath, 'utf-8')).toBe(content);
    });

    it('should set executable permissions', () => {
      const scriptPath = path.join(tempDir, 'test.sh');
      const content = '#!/bin/bash\necho "hello"\n';

      writeShellScript(content, scriptPath);

      const stat = fs.statSync(scriptPath);
      expect(stat.mode & 0o111).toBeTruthy();
    });

    it('should overwrite existing file', () => {
      const scriptPath = path.join(tempDir, 'test.sh');

      writeShellScript('first', scriptPath);
      writeShellScript('second', scriptPath);

      expect(fs.readFileSync(scriptPath, 'utf-8')).toBe('second');
    });
  });
});
