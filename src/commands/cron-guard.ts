import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';

interface CliOptions {
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

export interface CronGuardResult {
  success: boolean;
  healthy: boolean;
  jobsChecked: number;
  jobs: CronJob[];
  issues: CronGuardIssue[];
  message?: string;
}

const CLEAN_SWEEP_MARKER = 'clean-sweep';

const SUSPICIOUS_PATTERNS = [
  { pattern: /base64/i, severity: 'HIGH' as const, description: 'Base64 encoded command detected' },
  { pattern: /eval\s*\(/i, severity: 'HIGH' as const, description: 'PHP eval() pattern detected' },
  { pattern: /wget\s+http/i, severity: 'HIGH' as const, description: 'wget from external URL detected' },
  { pattern: /curl\s+http/i, severity: 'HIGH' as const, description: 'curl from external URL detected' },
  { pattern: /(\/dev\/null\s*2>&1|2>&1\s*>\s*\/dev\/null)/i, severity: 'MEDIUM' as const, description: 'Output suppression detected' },
  { pattern: /chmod\s+777/i, severity: 'MEDIUM' as const, description: 'Overly permissive chmod 777 detected' },
  { pattern: /passthru|shell_exec|system\s*\(/i, severity: 'MEDIUM' as const, description: 'Shell execution function detected' },
];

export function isCleanSweepLine(line: string): boolean {
  return line.includes(CLEAN_SWEEP_MARKER) && !line.trimStart().startsWith('#');
}

// ============================================================================
// Orphaned Cron Task Detection Functions
// ============================================================================

/**
 * Parse WordPress cron option from wp_options table
 * The cron option is a serialized PHP array with hook names as keys
 * 
 * CRON OPTION STRUCTURE:
 * a:N:{                    // Array with N cron entries
 *   s:LEN:"hook_name";     // Hook name (TOP-LEVEL key)
 *   a:2:{                  // Value object for this hook
 *     s:8:"schedule";      // Schedule type key (NOT a hook)
 *     s:5:"daily";         // Schedule value (NOT a hook)
 *     s:8:"args";          // Args key (NOT a hook)
 *     a:0:{}               // Empty args array
 *   }
 *   s:LEN:"next_hook";     // Next hook name (TOP-LEVEL key)
 *   ...
 * }
 * 
 * The regex captures ALL s:LEN:"..." strings, including:
 * - Top-level hook names (what we want)
 * - Inner keys like "schedule", "args" (false positives)
 * - Values like "daily", "hourly" (false positives)
 * 
 * To distinguish hook names from other strings:
 * 1. Hook names are followed by "a:{" (array/object value)
 * 2. Hook names must look like WordPress hook patterns:
 *    - start with wp_ (WordPress core)
 *    - contain underscores (plugin_slug_action format)
 * 3. Values like "daily", "hourly" don't match hook patterns
 */
export function parseWordPressCronOption(cronValue: string): string[] {
  const hooks: string[] = [];
  
  // Common non-hook string keys that appear in cron entry values
  // These are metadata keys, NOT cron hook names
  const KNOWN_NON_HOOKS = new Set([
    'schedule', 'args', 'callback', 'plugin', 'interval',
    'timestamp', 'slug', 'action', 'method', 'function',
    'url', 'key', 'secret', 'token', 'email', 'name',
    'id', 'type', 'status', 'priority', 'hook',
    // Common schedule values (not hooks, but appear as string values)
    'daily', 'hourly', 'twicedaily', 'weekly', 'monthly', 'yearly',
    'once', 'always', 'daily', 'twicedaily'
  ]);
  
  // WordPress stores cron as serialized PHP array
  // Pattern: s:LEN:"string_value" where LEN is the string length
  const stringPattern = /s:(\d+):"([^"]+)"/g;
  let match;
  
  while ((match = stringPattern.exec(cronValue)) !== null) {
    const [, lenStr, value] = match;
    const len = parseInt(lenStr, 10);
    
    // Validate: declared length must match actual length
    if (len !== value.length) {
      continue; // Malformed serialization
    }
    
    // Skip known non-hook keys (metadata keys in cron entry values)
    if (KNOWN_NON_HOOKS.has(value.toLowerCase())) {
      continue;
    }
    
    // Skip very short strings that are likely internal keys
    // Real WordPress hook names are typically 7+ characters
    if (value.length < 5) {
      continue;
    }
    
    // Skip numeric-only strings (array indices)
    if (/^\d+$/.test(value)) {
      continue;
    }
    
    // Validate hook name pattern
    // WordPress hook names follow these patterns:
    // - wp_* (WordPress core hooks)
    // - plugin_slug_action (plugin hooks with underscore separator)
    // - theme_slug_action (theme hooks with underscore separator)
    // - Must contain at least one underscore (except wp_* which starts with wp_)
    // - Must only contain alphanumeric, underscore, hyphen
    const isWpCore = value.startsWith('wp_');
    const hasUnderscore = value.includes('_');
    const hasHyphen = value.includes('-');
    const isValidChars = /^[a-zA-Z0-9_-]+$/.test(value);
    
    if (!isValidChars) {
      continue;
    }
    
    // Must be wp_* OR contain underscore/hyphen (plugin/theme naming)
    if (!isWpCore && !hasUnderscore && !hasHyphen) {
      continue;
    }
    
    // Hook names typically have a verb/action component after prefix
    // e.g., "wp_version_check" has prefix="wp" + action="version_check"
    // e.g., "pluginname_cron_action" has prefix="pluginname" + action="cron_action"
    // But we still include it (classification will determine severity)
    hooks.push(value);
  }
  
  return [...new Set(hooks)]; // Deduplicate
}

/**
 * Get WordPress core cron hook names
 * These are safe and should not be flagged as orphaned
 */
export function getWordPressCoreCronHooks(): Set<string> {
  return new Set([
    'wp_version_check',
    'wp_version_notify',
    'wp_privacy_delete_old_export_files',
    'wp_scheduled_delete',
    'wp_scheduled_auto_draft_delete',
    'wp_update_plugins',
    'wp_update_themes',
    'wp_post_thumbnail_internal_flush',
    'wp_batch_taxonomy_metadata',
    'wp_batch_term_metadata',
    'wp_update_option_upcoming_events_widget',
    'recovery_mode_clean_up',
    'recovery_mode_notification',
    'upgrader_scheduled_cleanup',
    'wp_ajax_nopriv_heartbeat',
    'wp_ajax_heartbeat',
    'wp_update_nav_menu_item',
    'wp_sites_close',
    'wp_maintenance',
    'wp_maybe_auto_update',
    'wp_generate_tag_cloud',
    'wp_update_feed_cached_data',
  ]);
}

/**
 * Check if a hook name appears to be randomly generated (malware indicator)
 */
export function isRandomGeneratedHook(hook: string): boolean {
  // Base64-like strings of reasonable length
  if (/^[A-Za-z0-9+\/=]{16,}$/.test(hook)) return true;
  
  // Random-looking hash pattern with underscores
  if (/^[a-z0-9]{10,}_[a-z0-9]{10,}$/i.test(hook)) return true;
  
  // Obfuscated pattern with numbers in unusual positions
  if (/^[a-z]+_[a-z]+_\d{4,}$/i.test(hook)) return true;
  
  // Mixed case base64-like with underscores
  if (/^[A-Za-z0-9]{8,}_[A-Za-z0-9]{8,}$/i.test(hook)) return true;
  
  return false;
}

/**
 * Check if hook callback contains malicious patterns in serialized data
 */
export function hasMaliciousCallback(cronEntry: string): boolean {
  const maliciousPatterns = [
    /eval\s*\(/i,
    /base64_decode\s*\(/i,
    /base64_encode\s*\(/i,
    /shell_exec\s*\(/i,
    /system\s*\(/i,
    /passthru\s*\(/i,
    /exec\s*\(/i,
    /preg_replace\s*.*\/e/i,
    /create_function\s*\(/i,
    /\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i,
  ];
  
  for (const pattern of maliciousPatterns) {
    if (pattern.test(cronEntry)) {
      return true;
    }
  }
  
  return false;
}

/**
 * Get installed plugin hooks by enumerating wp-content/plugins/
 */
export function getInstalledPluginHooks(targetPath: string): Map<string, string> {
  const pluginHooks = new Map<string, string>(); // hookPrefix -> pluginSlug
  
  const pluginsDir = path.join(targetPath, 'wp-content', 'plugins');
  
  if (!fs.existsSync(pluginsDir)) {
    return pluginHooks;
  }
  
  try {
    const pluginDirs = fs.readdirSync(pluginsDir, { withFileTypes: true });
    
    for (const dir of pluginDirs) {
      if (!dir.isDirectory()) continue;
      
      const pluginSlug = dir.name;
      
      // Store common prefixes (slug and slug with hyphens replaced by underscores)
      pluginHooks.set(pluginSlug, pluginSlug);
      pluginHooks.set(pluginSlug.replace(/-/g, '_'), pluginSlug);
      
      // Scan plugin main file for add_action/add_filter calls with cron hooks
      const mainFiles = ['index.php', `${pluginSlug}.php`];
      for (const mainFile of mainFiles) {
        const mainPath = path.join(pluginsDir, pluginSlug, mainFile);
        if (fs.existsSync(mainPath)) {
          try {
            const content = fs.readFileSync(mainPath, 'utf-8');
            // Match add_action( 'hook_name' ) and add_filter( 'hook_name' ) patterns
            const hookPattern = /add_(?:action|filter)\s*\([^)]*['"]([^'"]*(?:cron|schedule|scheduled|cronjob)[^'"]*)['"]/gi;
            let hookMatch;
            while ((hookMatch = hookPattern.exec(content)) !== null) {
              const hookName = hookMatch[1];
              // Extract prefix (first part before _)
              const prefix = hookName.split('_')[0];
              pluginHooks.set(prefix, pluginSlug);
              pluginHooks.set(prefix.replace(/-/g, '_'), pluginSlug);
            }
          } catch { /* skip individual file errors */ }
        }
      }
    }
  } catch { /* skip directory errors */ }
  
  return pluginHooks;
}

/**
 * Classify a cron hook and determine if it's orphaned
 */
export function classifyCronHook(
  hook: string,
  coreHooks: Set<string>,
  pluginHooks: Map<string, string>,
  activePlugins: string[]
): OrphanedCronEntry {
  // Check if it's a known WordPress core hook
  if (coreHooks.has(hook)) {
    return {
      hook,
      type: 'unknown',
      severity: 'LOW',
      reason: 'WordPress core cron hook'
    };
  }
  
  // Check if it matches any plugin hook pattern
  const hookPrefix = hook.split('_')[0];
  const pluginMatch = pluginHooks.get(hookPrefix);
  
  if (pluginMatch) {
    const isActive = activePlugins.some(p => 
      p.includes(pluginMatch) || pluginMatch.includes(p.replace(/_/g, '-'))
    );
    
    return {
      hook,
      type: 'unknown',
      severity: 'LOW',
      reason: `Likely belongs to plugin: ${pluginMatch}`,
      pluginMatch,
      isActivePlugin: isActive
    };
  }
  
  // Check for random-looking names (malware beacon indicator)
  if (isRandomGeneratedHook(hook)) {
    return {
      hook,
      type: 'suspicious',
      severity: 'HIGH',
      reason: 'Hook name appears randomly generated or obfuscated'
    };
  }
  
  // Unknown hook that doesn't match any known pattern - orphaned
  return {
    hook,
    type: 'orphaned',
    severity: 'MEDIUM',
    reason: 'No matching plugin or core hook found - may be orphaned from deleted plugin'
  };
}

export function isDisabledCleanSweepLine(line: string): boolean {
  const trimmed = line.trimStart();
  return trimmed.startsWith('# ') && trimmed.includes(CLEAN_SWEEP_MARKER);
}

export function parseCrontab(crontab: string): CronJob[] {
  const lines = crontab.split('\n');
  const jobs: CronJob[] = [];
  let id = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    if (trimmed === '' || (trimmed.startsWith('#') && !isDisabledCleanSweepLine(trimmed))) {
      continue;
    }

    if (isCleanSweepLine(trimmed)) {
      const parts = trimmed.split(/\s+/);
      const expression = parts.slice(0, 5).join(' ');
      const command = parts.slice(5).join(' ');
      jobs.push({ id: id++, expression, command, enabled: true, rawLine: trimmed, lineNumber: i + 1 });
    } else if (isDisabledCleanSweepLine(trimmed)) {
      const uncommented = trimmed.replace(/^#\s*/, '');
      const parts = uncommented.split(/\s+/);
      const expression = parts.slice(0, 5).join(' ');
      const command = parts.slice(5).join(' ');
      jobs.push({ id: id++, expression, command, enabled: false, rawLine: trimmed, lineNumber: i + 1 });
    }
  }

  return jobs;
}

export function isValidCronExpression(expression: string): boolean {
  const parts = expression.split(/\s+/);
  if (parts.length !== 5) {
    return false;
  }

  const patterns = [
    /^(\*|[0-9]|[1-5][0-9])(-(\*|[0-9]|[1-5][0-9]))?$/,
    /^(\*|[0-9]|[1-5][0-9])(-(\*|[0-9]|[1-5][0-9]))?(\/(\d+))?$/,
    /^(\*|[0-9]|[1-5][0-9])(,(\*|[0-9]|[1-5][0-9]))*$/,
    /^\*$|^\*\/[0-9]+$|^[0-9]+(-[0-9]+)?(\/[0-9]+)?$|^[0-9]+(,[0-9]+)*$/,
  ];

  for (let i = 0; i < 5; i++) {
    const part = parts[i];
    const valid = /^\*$|^\*\/[0-9]+$|^[0-9]+(-[0-9]+)?(\/[0-9]+)?$|^[0-9]+(,[0-9]+)*$/.test(part);
    if (!valid) {
      return false;
    }
  }

  return true;
}

export function extractCommandPath(command: string): string {
  const parts = command.split(/\s+/);
  let cmdPath = parts[0];

  if (cmdPath.startsWith('/')) {
    return cmdPath;
  }

  if (cmdPath.startsWith('=') || cmdPath.startsWith('$')) {
    const match = command.match(/^([^\s=]+=)[^\s]+/);
    if (match) {
      cmdPath = match[1];
    }
  }

  return cmdPath;
}

export function checkCommandPath(command: string, checkFn?: (p: string) => boolean): boolean {
  const cmdPath = extractCommandPath(command);

  if (!cmdPath.startsWith('/')) {
    return true;
  }

  if (cmdPath.includes('$') || cmdPath.includes('=')) {
    return true;
  }

  if (checkFn) {
    return checkFn(cmdPath);
  }

  try {
    return fs.existsSync(cmdPath);
  } catch {
    return false;
  }
}

export function detectSuspiciousModifications(job: CronJob): CronGuardIssue[] {
  const issues: CronGuardIssue[] = [];

  for (const { pattern, severity, description } of SUSPICIOUS_PATTERNS) {
    if (pattern.test(job.command)) {
      issues.push({
        type: 'suspicious',
        severity,
        jobId: job.id,
        message: description,
        details: `Line ${job.lineNumber}: ${job.rawLine}`,
      });
    }
  }

  return issues;
}

export function getSeverityForInterval(minutes: number): FrequencyAnalysis['severity'] {
  if (minutes <= 1) return 'CRITICAL';
  if (minutes <= 5) return 'HIGH';
  if (minutes <= 15) return 'MEDIUM';
  if (minutes <= 30) return 'LOW';
  return 'NORMAL';
}

export function analyzeCronFrequency(expression: string): FrequencyAnalysis | null {
  const parts = expression.split(/\s+/);
  if (parts.length !== 5) {
    return null;
  }

  const [minute, hour, , ,] = parts;

  // Detect wildcard minute with step (e.g., */5, */10, */15)
  const minuteStepMatch = minute.match(/^\*\/(\d+)$/);
  if (minuteStepMatch) {
    const interval = parseInt(minuteStepMatch[1], 10);
    if (interval <= 0 || interval > 59) {
      return null;
    }
    const runsPerDay = Math.floor(1440 / interval);

    return {
      expression,
      runsPerDay,
      intervalMinutes: interval,
      severity: getSeverityForInterval(interval),
      description: `Every ${interval} minute${interval > 1 ? 's' : ''} (${runsPerDay} runs/day)`,
    };
  }

  // Every minute wildcard (* * * * *)
  if (minute === '*' && hour === '*') {
    return {
      expression,
      runsPerDay: 1440,
      intervalMinutes: 1,
      severity: 'CRITICAL',
      description: 'Every minute (1440 runs/day) - malware beacon pattern',
    };
  }

  // Specific minutes list (e.g., 0,15,30,45 * * * * = every 15 min)
  const minuteListMatch = minute.match(/^(\d+,)*\d+$/);
  if (minuteListMatch && hour === '*') {
    const minutes = minute.split(',').map((m) => parseInt(m, 10)).filter((m) => m >= 0 && m <= 59);
    if (minutes.length > 1) {
      // Sort and find gaps
      minutes.sort((a, b) => a - b);
      let minGap = 60;
      for (let i = 0; i < minutes.length - 1; i++) {
        const gap = minutes[i + 1] - minutes[i];
        if (gap < minGap) minGap = gap;
      }
      // Also check wraparound gap
      const wraparoundGap = (60 - minutes[minutes.length - 1]) + minutes[0];
      if (wraparoundGap < minGap) minGap = wraparoundGap;

      const runsPerDay = minutes.length * 24;
      return {
        expression,
        runsPerDay,
        intervalMinutes: minGap,
        severity: getSeverityForInterval(minGap),
        description: `Every ${minGap} minute${minGap > 1 ? 's' : ''} (${runsPerDay} runs/day)`,
      };
    }
  }

  // Range with step (e.g., 0-30/5 * * * *)
  const rangeStepMatch = minute.match(/^(\d+)-(\d+)\/(\d+)$/);
  if (rangeStepMatch) {
    const [, startStr, endStr, stepStr] = rangeStepMatch;
    const start = parseInt(startStr, 10);
    const end = parseInt(endStr, 10);
    const step = parseInt(stepStr, 10);
    if (step > 0) {
      const runsPerDay = Math.floor(((end - start) / step) + 1) * 24;
      return {
        expression,
        runsPerDay,
        intervalMinutes: step,
        severity: getSeverityForInterval(step),
        description: `Every ${step} minute${step > 1 ? 's' : ''} during ${start}-${end} (${runsPerDay} runs/day)`,
      };
    }
  }

  // Single specific minute (e.g., 30 * * * * = every hour at :30)
  const singleMinuteMatch = minute.match(/^(\d+)$/);
  if (singleMinuteMatch && hour === '*') {
    const minuteVal = parseInt(singleMinuteMatch[1], 10);
    if (minuteVal >= 0 && minuteVal <= 59) {
      return {
        expression,
        runsPerDay: 24,
        intervalMinutes: 60,
        severity: 'NORMAL',
        description: 'Every hour at minute ' + minuteVal,
      };
    }
  }

  return null;
}

export function guardJobs(jobs: CronJob[], checkFn?: (p: string) => boolean): CronGuardResult {
  const issues: CronGuardIssue[] = [];

  for (const job of jobs) {
    if (!job.enabled) {
      issues.push({
        type: 'disabled',
        severity: 'HIGH',
        jobId: job.id,
        message: `Clean-sweep job ${job.id} is disabled`,
        details: `Line ${job.lineNumber}: ${job.rawLine}`,
      });
    }

    if (!isValidCronExpression(job.expression)) {
      issues.push({
        type: 'invalid_expression',
        severity: 'MEDIUM',
        jobId: job.id,
        message: `Job ${job.id} has invalid cron expression: ${job.expression}`,
        details: `Line ${job.lineNumber}: ${job.rawLine}`,
      });
    }

    if (!checkCommandPath(job.command, checkFn)) {
      issues.push({
        type: 'path_not_found',
        severity: 'HIGH',
        jobId: job.id,
        message: `Job ${job.id} references non-existent path: ${extractCommandPath(job.command)}`,
        details: `Line ${job.lineNumber}: ${job.rawLine}`,
      });
    }

    const suspiciousIssues = detectSuspiciousModifications(job);
    issues.push(...suspiciousIssues);

    // Check execution frequency
    const frequency = analyzeCronFrequency(job.expression);
    if (frequency && frequency.severity !== 'NORMAL') {
      issues.push({
        type: 'excessive_frequency',
        severity: frequency.severity as 'HIGH' | 'MEDIUM' | 'LOW',
        jobId: job.id,
        message: `Suspicious execution frequency: ${frequency.description}`,
        details: `Line ${job.lineNumber}: ${job.rawLine}`,
      });
    }
  }

  return {
    success: true,
    healthy: issues.length === 0,
    jobsChecked: jobs.length,
    jobs,
    issues,
  };
}

/**
 * Detect orphaned WordPress cron tasks
 * Analyzes the cron option from wp_options to find hooks from deleted plugins
 */
export function detectOrphanedCronJobs(
  targetPath: string,
  cronOptionValue?: string,
  activePluginsOption?: string[]
): OrphanedCronResult {
  const issues: CronGuardIssue[] = [];
  
  // Get WordPress core hooks (whitelist)
  const coreHooks = getWordPressCoreCronHooks();
  
  // Get installed plugin hooks
  const pluginHooks = getInstalledPluginHooks(targetPath);
  
  // Parse active plugins if provided
  const activePlugins = activePluginsOption || [];
  
  // Parse cron hooks if provided
  const cronHooks = cronOptionValue 
    ? parseWordPressCronOption(cronOptionValue)
    : [];
  
  // Classify each cron hook
  const orphanedJobs: OrphanedCronEntry[] = [];
  
  for (const hook of cronHooks) {
    const entry = classifyCronHook(hook, coreHooks, pluginHooks, activePlugins);
    
    // Only report problematic hooks (orphaned, suspicious, malicious)
    if (entry.type === 'orphaned' || entry.type === 'suspicious' || entry.type === 'malicious') {
      orphanedJobs.push(entry);
      
      issues.push({
        type: 'orphaned',
        severity: entry.severity as 'HIGH' | 'MEDIUM' | 'LOW',
        message: `Orphaned cron hook detected: ${hook}`,
        details: entry.reason
      });
    }
  }
  
  return {
    success: true,
    cronOptionsFound: cronHooks.length > 0,
    totalScheduledJobs: cronHooks.length,
    orphanedJobs,
    activePlugins,
    installedPlugins: Array.from(pluginHooks.values()),
    issues
  };
}

export function readCrontab(readFn?: () => string): string {
  if (readFn) {
    return readFn();
  }
  return '';
}

export function checkCrontabGuard(crontab: string, checkFn?: (p: string) => boolean): CronGuardResult {
  if (!crontab || crontab.trim() === '') {
    return {
      success: true,
      healthy: false,
      jobsChecked: 0,
      jobs: [],
      issues: [{
        type: 'missing',
        severity: 'HIGH',
        message: 'No crontab found or crontab is empty',
      }],
    };
  }

  const jobs = parseCrontab(crontab);

  if (jobs.length === 0) {
    return {
      success: true,
      healthy: false,
      jobsChecked: 0,
      jobs: [],
      issues: [{
        type: 'missing',
        severity: 'HIGH',
        message: 'No clean-sweep cron jobs found in crontab',
      }],
    };
  }

  return guardJobs(jobs, checkFn);
}

function formatOutput(data: unknown, useJson: boolean): void {
  if (useJson) {
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(data);
  }
}

function printResults(result: CronGuardResult): void {
  console.log('Clean Sweep Cron Guard');
  console.log('=====================');
  console.log(`\nTotal clean-sweep jobs checked: ${result.jobsChecked}`);

  if (result.jobs.length > 0) {
    console.log('\nClean-sweep Jobs:');
    console.log('-'.repeat(80));
    console.log(
      ' ' + 'ID'.padEnd(5) +
      'Status'.padEnd(10) +
      'Schedule'.padEnd(20) +
      'Command'
    );
    console.log('-'.repeat(80));

    for (const job of result.jobs) {
      const status = job.enabled ? 'enabled' : 'disabled';
      console.log(
        ' ' + String(job.id).padEnd(5) +
        status.padEnd(10) +
        job.expression.padEnd(20) +
        job.command
      );
    }
    console.log('-'.repeat(80));
  }

  if (result.issues.length === 0) {
    console.log('\nAll clean-sweep cron jobs are healthy.');
    return;
  }

  console.log(`\nIssues found: ${result.issues.length}`);

  const highSeverity = result.issues.filter((e) => e.severity === 'HIGH');
  const mediumSeverity = result.issues.filter((e) => e.severity === 'MEDIUM');
  const lowSeverity = result.issues.filter((e) => e.severity === 'LOW');

  if (highSeverity.length > 0) {
    console.log(`\n[HIGH severity: ${highSeverity.length}]`);
    for (const issue of highSeverity) {
      console.log(`  ${issue.message}`);
      if (issue.details) {
        console.log(`    ${issue.details}`);
      }
    }
  }

  if (mediumSeverity.length > 0) {
    console.log(`\n[MEDIUM severity: ${mediumSeverity.length}]`);
    for (const issue of mediumSeverity) {
      console.log(`  ${issue.message}`);
      if (issue.details) {
        console.log(`    ${issue.details}`);
      }
    }
  }

  if (lowSeverity.length > 0) {
    console.log(`\n[LOW severity: ${lowSeverity.length}]`);
    for (const issue of lowSeverity) {
      console.log(`  ${issue.message}`);
      if (issue.details) {
        console.log(`    ${issue.details}`);
      }
    }
  }
}

export function registerCronGuardCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  program
    .command('cron:guard')
    .description('Monitor clean-sweep cron jobs to ensure they are running properly')
    .option('--json', 'Output results as JSON', false)
    .action((cmdOptions) => {
      const opts = getOpts();
      const useJson = opts.json || cmdOptions.json;

      try {
        const crontab = readCrontab(() => {
          const { execSync } = require('child_process');
          try {
            return execSync('crontab -l', { encoding: 'utf-8' });
          } catch {
            return '';
          }
        });

        const result = checkCrontabGuard(crontab);

        if (useJson) {
          formatOutput(result, true);
        } else {
          printResults(result);
        }

        process.exit(result.healthy ? 0 : 1);
      } catch (err) {
        const error = {
          success: false,
          healthy: false,
          jobsChecked: 0,
          jobs: [],
          issues: [],
          message: String(err),
        };
        formatOutput(error, useJson);
        process.exit(1);
      }
    });
}
