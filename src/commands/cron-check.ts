import { Command } from 'commander';

interface CliOptions {
  dryRun: boolean;
  force: boolean;
  json: boolean;
  path: string;
  verbose: boolean;
}

export interface SuspiciousCronEntry {
  line: string;
  lineNumber: number;
  pattern: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
}

export interface CronCheckResult {
  success: boolean;
  entriesParsed: number;
  suspiciousEntries: SuspiciousCronEntry[];
  hasSuspicious: boolean;
  message?: string;
}

const SUSPICIOUS_PATTERNS = [
  {
    pattern: /base64/i,
    severity: 'HIGH' as const,
    description: 'Base64 encoded command detected',
  },
  {
    pattern: /eval\s*\(/i,
    severity: 'HIGH' as const,
    description: 'PHP eval() pattern detected',
  },
  {
    pattern: /wget\s+http/i,
    severity: 'HIGH' as const,
    description: 'wget from external URL detected',
  },
  {
    pattern: /curl\s+http/i,
    severity: 'HIGH' as const,
    description: 'curl from external URL detected',
  },
  {
    // Match /tmp/ but NOT when preceded by /var (i.e., /var/tmp/)
    pattern: /(?<!\/var)\/tmp\//,
    severity: 'HIGH' as const,
    description: 'Command references /tmp directory',
  },
  {
    pattern: /\/var\/tmp\//,
    severity: 'HIGH' as const,
    description: 'Command references /var/tmp directory',
  },
  {
    pattern: /chmod\s+777/,
    severity: 'MEDIUM' as const,
    description: 'Overly permissive chmod 777 detected',
  },
  {
    pattern: /chmod\s+755\s+.*\/bin\//,
    severity: 'MEDIUM' as const,
    description: 'Making binaries world-executable detected',
  },
  {
    pattern: /disable_functions|open_basedir.*none/i,
    severity: 'MEDIUM' as const,
    description: 'Attempting to disable PHP security features',
  },
  {
    pattern: /passthru|shell_exec|system\s*\(/i,
    severity: 'MEDIUM' as const,
    description: 'Shell execution function detected',
  },
  {
    pattern: /unknown/i,
    severity: 'LOW' as const,
    description: 'Unknown command or script detected',
  },
  {
    pattern: /cron/i,
    severity: 'LOW' as const,
    description: 'Cron-related command detected',
  },
];

const MALWARE_PERSISTENCE_PATTERNS = [
  {
    pattern: /\.ssh\/authorized_keys/,
    severity: 'HIGH' as const,
    description: 'SSH authorized keys modification detected',
  },
  {
    pattern: /\.bashrc|\.bash_profile|\.profile/,
    severity: 'MEDIUM' as const,
    description: 'Shell profile modification detected',
  },
  {
    pattern: /cron\.sh|wget.*cron|curl.*cron/i,
    severity: 'HIGH' as const,
    description: 'Suspicious cron download pattern detected',
  },
  {
    pattern: /rm\s+-rf\s+.*\/tmp/,
    severity: 'MEDIUM' as const,
    description: 'Suspicious file deletion in /tmp',
  },
  {
    pattern: /nc\s+|netcat|nmap/i,
    severity: 'HIGH' as const,
    description: 'Network tunneling tool detected',
  },
  {
    pattern: /python.*-c\s+.*exec/i,
    severity: 'HIGH' as const,
    description: 'Python inline code execution detected',
  },
  {
    pattern: /bash\s+-i/i,
    severity: 'HIGH' as const,
    description: 'Interactive bash shell detected',
  },
  {
    pattern: /(\/dev\/null\s*2>&1|2>&1\s*>\s*\/dev\/null)/i,
    severity: 'MEDIUM' as const,
    description: 'Output suppression detected (hiding execution)',
  },
];

const SUSPICIOUS_HOSTS = [
  / Paste suspicious host patterns here as needed /i,
];

export function parseCronEntry(line: string, lineNumber: number): SuspiciousCronEntry[] {
  const entries: SuspiciousCronEntry[] = [];
  const trimmed = line.trim();

  if (trimmed === '' || trimmed.startsWith('#')) {
    return entries;
  }

  for (const { pattern, severity, description } of SUSPICIOUS_PATTERNS) {
    if (pattern.test(trimmed)) {
      entries.push({
        line: trimmed,
        lineNumber,
        pattern: pattern.toString(),
        severity,
        description,
      });
    }
  }

  for (const { pattern, severity, description } of MALWARE_PERSISTENCE_PATTERNS) {
    if (pattern.test(trimmed)) {
      entries.push({
        line: trimmed,
        lineNumber,
        pattern: pattern.toString(),
        severity,
        description,
      });
    }
  }

  return entries;
}

export function parseCrontab(crontab: string): string[] {
  return crontab.split('\n');
}

export function checkCrontab(crontab: string): CronCheckResult {
  const lines = parseCrontab(crontab);
  const suspiciousEntries: SuspiciousCronEntry[] = [];
  let entryCount = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    if (trimmed === '' || trimmed.startsWith('#')) {
      continue;
    }

    entryCount++;

    const suspicious = parseCronEntry(line, i + 1);
    suspiciousEntries.push(...suspicious);
  }

  return {
    success: true,
    entriesParsed: entryCount,
    suspiciousEntries,
    hasSuspicious: suspiciousEntries.length > 0,
  };
}

export function readCrontab(readFn?: () => string): string {
  if (readFn) {
    return readFn();
  }
  return '';
}

function formatOutput(data: unknown, useJson: boolean): void {
  if (useJson) {
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(data);
  }
}

function printResults(result: CronCheckResult): void {
  console.log('Cron Security Check');
  console.log('===================');
  console.log(`\nTotal cron entries scanned: ${result.entriesParsed}`);

  if (result.suspiciousEntries.length === 0) {
    console.log('\nNo suspicious cron entries found.');
    console.log('Your crontab appears to be clean.');
    return;
  }

  console.log(`\nSuspicious entries found: ${result.suspiciousEntries.length}`);

  const highSeverity = result.suspiciousEntries.filter((e) => e.severity === 'HIGH');
  const mediumSeverity = result.suspiciousEntries.filter((e) => e.severity === 'MEDIUM');
  const lowSeverity = result.suspiciousEntries.filter((e) => e.severity === 'LOW');

  if (highSeverity.length > 0) {
    console.log(`\n[HIGH severity: ${highSeverity.length}]`);
    for (const entry of highSeverity) {
      console.log(`  Line ${entry.lineNumber}: ${entry.description}`);
      console.log(`    Command: ${entry.line}`);
    }
  }

  if (mediumSeverity.length > 0) {
    console.log(`\n[MEDIUM severity: ${mediumSeverity.length}]`);
    for (const entry of mediumSeverity) {
      console.log(`  Line ${entry.lineNumber}: ${entry.description}`);
      console.log(`    Command: ${entry.line}`);
    }
  }

  if (lowSeverity.length > 0) {
    console.log(`\n[LOW severity: ${lowSeverity.length}]`);
    for (const entry of lowSeverity) {
      console.log(`  Line ${entry.lineNumber}: ${entry.description}`);
      console.log(`    Command: ${entry.line}`);
    }
  }
}

export function registerCronCheckCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  program
    .command('cron:check')
    .description('Check crontab for suspicious or malicious entries')
    .option('--json', 'Output results as JSON', false)
    .action((cmdOptions) => {
      const opts = getOpts();
      const useJson = opts.json || cmdOptions.json;

      try {
        const crontab = readCrontab(() => {
          const { execSync } = require('child_process');
          try {
            return execSync('crontab -l 2>/dev/null', { encoding: 'utf-8' });
          } catch {
            return '';
          }
        });

        if (crontab === '') {
          const result: CronCheckResult = {
            success: true,
            entriesParsed: 0,
            suspiciousEntries: [],
            hasSuspicious: false,
            message: 'No crontab found or crontab is empty',
          };

          if (useJson) {
            formatOutput(result, true);
          } else {
            console.log('Cron Security Check');
            console.log('===================');
            console.log('\nNo crontab found or crontab is empty.');
          }
          process.exit(0);
        }

        const result = checkCrontab(crontab);

        if (useJson) {
          formatOutput(result, true);
        } else {
          printResults(result);
        }

        process.exit(result.hasSuspicious ? 1 : 0);
      } catch (err) {
        const error = {
          success: false,
          error: 'Failed to check crontab',
          message: String(err),
        };
        formatOutput(error, useJson);
        process.exit(1);
      }
    });
}
