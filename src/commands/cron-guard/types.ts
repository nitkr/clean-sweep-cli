export interface CliOptions {
  dryRun: boolean;
  force: boolean;
  json: boolean;
  path: string;
  verbose: boolean;
}

export interface CronJob {
  id: number;
  expression: string;
  command: string;
  enabled: boolean;
  rawLine: string;
  lineNumber: number;
}

export interface CronGuardIssue {
  type: 'missing' | 'disabled' | 'invalid_expression' | 'path_not_found' | 'modified' | 'suspicious' | 'excessive_frequency' | 'orphaned';
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  jobId?: number;
  message: string;
  details?: string;
}

export interface OrphanedCronEntry {
  hook: string;
  type: 'orphaned' | 'unknown' | 'suspicious' | 'malicious';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  reason: string;
  details?: string;
  pluginMatch?: string;
  isActivePlugin?: boolean;
}

export interface OrphanedCronResult {
  success: boolean;
  cronOptionsFound: boolean;
  totalScheduledJobs: number;
  orphanedJobs: OrphanedCronEntry[];
  activePlugins: string[];
  installedPlugins: string[];
  issues: CronGuardIssue[];
}

export interface FrequencyAnalysis {
  expression: string;
  runsPerDay: number;
  intervalMinutes: number | null;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NORMAL';
  description: string;
}

export interface CronPurgeResult {
  success: boolean;
  totalHooks: number;
  hooksDeleted: number;
  hooksPreserved: number;
  deletedHooks: string[];
  preservedHooks: string[];
  backupCreated: boolean;
  message: string;
}

export interface CronGuardResult {
  success: boolean;
  healthy: boolean;
  jobsChecked: number;
  jobs: CronJob[];
  issues: CronGuardIssue[];
  message?: string;
}

export const CLEAN_SWEEP_MARKER = 'clean-sweep';

export const SUSPICIOUS_PATTERNS = [
  { pattern: /base64/i, severity: 'HIGH' as const, description: 'Base64 encoded command detected' },
  { pattern: /eval\s*\(/i, severity: 'HIGH' as const, description: 'PHP eval() pattern detected' },
  { pattern: /wget\s+http/i, severity: 'HIGH' as const, description: 'wget from external URL detected' },
  { pattern: /curl\s+http/i, severity: 'HIGH' as const, description: 'curl from external URL detected' },
  { pattern: /(\/dev\/null\s*2>&1|2>&1\s*>\s*\/dev\/null)/i, severity: 'MEDIUM' as const, description: 'Output suppression detected' },
  { pattern: /chmod\s+777/i, severity: 'MEDIUM' as const, description: 'Overly permissive chmod 777 detected' },
  { pattern: /passthru|shell_exec|system\s*\(/i, severity: 'MEDIUM' as const, description: 'Shell execution function detected' },
];
