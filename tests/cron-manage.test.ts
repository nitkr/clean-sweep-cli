import { describe, it, expect } from '@jest/globals';
import {
  parseCrontab,
  isCleanSweepLine,
  isDisabledCleanSweepLine,
  toggleCronJob,
  listJobs,
  enableJob,
  disableJob,
  CronJob,
} from '../src/commands/cron-manage';

describe('Cron Manage Module', () => {
  describe('isCleanSweepLine', () => {
    it('should return true for active clean-sweep cron lines', () => {
      expect(isCleanSweepLine('0 2 * * * /bin/bash /scripts/clean-sweep-daily.sh')).toBe(true);
    });

    it('should return false for commented-out lines', () => {
      expect(isCleanSweepLine('# 0 2 * * * /bin/bash /scripts/clean-sweep-daily.sh')).toBe(false);
    });

    it('should return false for non-clean-sweep lines', () => {
      expect(isCleanSweepLine('0 2 * * * /usr/bin/backup.sh')).toBe(false);
    });

    it('should return false for empty lines', () => {
      expect(isCleanSweepLine('')).toBe(false);
    });
  });

  describe('isDisabledCleanSweepLine', () => {
    it('should return true for commented-out clean-sweep lines', () => {
      expect(isDisabledCleanSweepLine('# 0 2 * * * /bin/bash /scripts/clean-sweep-daily.sh')).toBe(true);
    });

    it('should return false for active clean-sweep lines', () => {
      expect(isDisabledCleanSweepLine('0 2 * * * /bin/bash /scripts/clean-sweep-daily.sh')).toBe(false);
    });

    it('should return false for other comments', () => {
      expect(isDisabledCleanSweepLine('# some other comment')).toBe(false);
    });
  });

  describe('parseCrontab', () => {
    it('should return empty array for empty crontab', () => {
      const result = parseCrontab('');
      expect(result).toEqual([]);
    });

    it('should parse active clean-sweep jobs', () => {
      const crontab = '0 2 * * * /bin/bash /scripts/clean-sweep-daily.sh';
      const result = parseCrontab(crontab);

      expect(result).toHaveLength(1);
      expect(result[0].expression).toBe('0 2 * * *');
      expect(result[0].command).toBe('/bin/bash /scripts/clean-sweep-daily.sh');
      expect(result[0].enabled).toBe(true);
    });

    it('should parse disabled clean-sweep jobs', () => {
      const crontab = '# 0 2 * * * /bin/bash /scripts/clean-sweep-daily.sh';
      const result = parseCrontab(crontab);

      expect(result).toHaveLength(1);
      expect(result[0].expression).toBe('0 2 * * *');
      expect(result[0].command).toBe('/bin/bash /scripts/clean-sweep-daily.sh');
      expect(result[0].enabled).toBe(false);
    });

    it('should skip non-clean-sweep lines', () => {
      const crontab = [
        '0 1 * * * /usr/bin/backup.sh',
        '0 2 * * * /bin/bash /scripts/clean-sweep-daily.sh',
        '# comment',
      ].join('\n');

      const result = parseCrontab(crontab);
      expect(result).toHaveLength(1);
      expect(result[0].expression).toBe('0 2 * * *');
    });

    it('should assign incrementing ids', () => {
      const crontab = [
        '0 2 * * * /bin/bash /scripts/clean-sweep-daily.sh',
        '# 0 3 * * 0 /bin/bash /scripts/clean-sweep-weekly.sh',
        '0 4 1 * * /bin/bash /scripts/clean-sweep-monthly.sh',
      ].join('\n');

      const result = parseCrontab(crontab);
      expect(result).toHaveLength(3);
      expect(result[0].id).toBe(0);
      expect(result[1].id).toBe(1);
      expect(result[2].id).toBe(2);
    });

    it('should handle mixed crontab with comments and blank lines', () => {
      const crontab = [
        '# m h dom mon dow command',
        '',
        '0 1 * * * /usr/bin/backup.sh',
        '',
        '0 2 * * * /bin/bash /scripts/clean-sweep-daily.sh',
        '# 0 3 * * 0 /bin/bash /scripts/clean-sweep-weekly.sh',
      ].join('\n');

      const result = parseCrontab(crontab);
      expect(result).toHaveLength(2);
      expect(result[0].enabled).toBe(true);
      expect(result[1].enabled).toBe(false);
    });
  });

  describe('toggleCronJob', () => {
    it('should disable an active job', () => {
      const crontab = '0 2 * * * /bin/bash /scripts/clean-sweep-daily.sh';
      const { updated, job } = toggleCronJob(crontab, 0, false);

      expect(job).not.toBeNull();
      expect(job!.enabled).toBe(false);
      expect(updated).toBe('# 0 2 * * * /bin/bash /scripts/clean-sweep-daily.sh');
    });

    it('should enable a disabled job', () => {
      const crontab = '# 0 2 * * * /bin/bash /scripts/clean-sweep-daily.sh';
      const { updated, job } = toggleCronJob(crontab, 0, true);

      expect(job).not.toBeNull();
      expect(job!.enabled).toBe(true);
      expect(updated).toBe('0 2 * * * /bin/bash /scripts/clean-sweep-daily.sh');
    });

    it('should return null job for non-existent id', () => {
      const crontab = '0 2 * * * /bin/bash /scripts/clean-sweep-daily.sh';
      const { job } = toggleCronJob(crontab, 99, false);

      expect(job).toBeNull();
    });

    it('should leave crontab unchanged for non-existent id', () => {
      const crontab = '0 2 * * * /bin/bash /scripts/clean-sweep-daily.sh';
      const { updated } = toggleCronJob(crontab, 99, false);

      expect(updated).toBe(crontab);
    });

    it('should not re-disable an already disabled job', () => {
      const crontab = '# 0 2 * * * /bin/bash /scripts/clean-sweep-daily.sh';
      const { updated, job } = toggleCronJob(crontab, 0, false);

      expect(job).not.toBeNull();
      expect(job!.enabled).toBe(false);
      expect(updated).toBe(crontab);
    });

    it('should not re-enable an already active job', () => {
      const crontab = '0 2 * * * /bin/bash /scripts/clean-sweep-daily.sh';
      const { updated, job } = toggleCronJob(crontab, 0, true);

      expect(job).not.toBeNull();
      expect(job!.enabled).toBe(true);
      expect(updated).toBe(crontab);
    });

    it('should toggle correct job when multiple exist', () => {
      const crontab = [
        '0 2 * * * /bin/bash /scripts/clean-sweep-daily.sh',
        '0 3 * * 0 /bin/bash /scripts/clean-sweep-weekly.sh',
      ].join('\n');

      const { updated, job } = toggleCronJob(crontab, 1, false);

      expect(job).not.toBeNull();
      expect(job!.expression).toBe('0 3 * * 0');
      expect(job!.enabled).toBe(false);
      expect(updated).toContain('0 2 * * * /bin/bash /scripts/clean-sweep-daily.sh');
      expect(updated).toContain('# 0 3 * * 0 /bin/bash /scripts/clean-sweep-weekly.sh');
    });
  });

  describe('listJobs', () => {
    it('should return list result with all jobs', () => {
      const crontab = [
        '0 2 * * * /bin/bash /scripts/clean-sweep-daily.sh',
        '# 0 3 * * 0 /bin/bash /scripts/clean-sweep-weekly.sh',
      ].join('\n');

      const result = listJobs(crontab);

      expect(result.success).toBe(true);
      expect(result.action).toBe('list');
      expect(result.jobs).toHaveLength(2);
      expect(result.jobs[0].enabled).toBe(true);
      expect(result.jobs[1].enabled).toBe(false);
    });

    it('should return empty list when no jobs exist', () => {
      const result = listJobs('');

      expect(result.success).toBe(true);
      expect(result.action).toBe('list');
      expect(result.jobs).toHaveLength(0);
    });
  });

  describe('enableJob', () => {
    it('should return success for valid disabled job', () => {
      const crontab = '# 0 2 * * * /bin/bash /scripts/clean-sweep-daily.sh';
      const result = enableJob(crontab, 0);

      expect(result.success).toBe(true);
      expect(result.action).toBe('enable');
      expect(result.jobs).toHaveLength(1);
      expect(result.jobs[0].enabled).toBe(true);
    });

    it('should return failure for non-existent job', () => {
      const crontab = '0 2 * * * /bin/bash /scripts/clean-sweep-daily.sh';
      const result = enableJob(crontab, 99);

      expect(result.success).toBe(false);
      expect(result.message).toContain('not found');
    });
  });

  describe('disableJob', () => {
    it('should return success for valid active job', () => {
      const crontab = '0 2 * * * /bin/bash /scripts/clean-sweep-daily.sh';
      const result = disableJob(crontab, 0);

      expect(result.success).toBe(true);
      expect(result.action).toBe('disable');
      expect(result.jobs).toHaveLength(1);
      expect(result.jobs[0].enabled).toBe(false);
    });

    it('should return failure for non-existent job', () => {
      const crontab = '0 2 * * * /bin/bash /scripts/clean-sweep-daily.sh';
      const result = disableJob(crontab, 99);

      expect(result.success).toBe(false);
      expect(result.message).toContain('not found');
    });
  });
});
