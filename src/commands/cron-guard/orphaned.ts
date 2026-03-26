import * as fs from 'fs';
import * as path from 'path';
import {
  OrphanedCronEntry,
  CronGuardIssue,
  OrphanedCronResult,
} from './types';

export { OrphanedCronEntry, OrphanedCronResult };

export function parseWordPressCronOption(cronValue: string): string[] {
  const hooks: string[] = [];

  const KNOWN_NON_HOOKS = new Set([
    'schedule', 'args', 'callback', 'plugin', 'interval',
    'timestamp', 'slug', 'action', 'method', 'function',
    'url', 'key', 'secret', 'token', 'email', 'name',
    'id', 'type', 'status', 'priority', 'hook',
    'daily', 'hourly', 'twicedaily', 'weekly', 'monthly', 'yearly',
    'once', 'always', 'daily', 'twicedaily'
  ]);

  const stringPattern = /s:(\d+):"([^"]+)"/g;
  let match;

  while ((match = stringPattern.exec(cronValue)) !== null) {
    const [, lenStr, value] = match;
    const len = parseInt(lenStr, 10);

    if (len !== value.length) {
      continue;
    }

    if (KNOWN_NON_HOOKS.has(value.toLowerCase())) {
      continue;
    }

    if (value.length < 5) {
      continue;
    }

    if (/^\d+$/.test(value)) {
      continue;
    }

    const isWpCore = value.startsWith('wp_');
    const hasUnderscore = value.includes('_');
    const hasHyphen = value.includes('-');
    const isValidChars = /^[a-zA-Z0-9_-]+$/.test(value);

    if (!isValidChars) {
      continue;
    }

    if (!isWpCore && !hasUnderscore && !hasHyphen) {
      continue;
    }

    hooks.push(value);
  }

  return [...new Set(hooks)];
}

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

export function isRandomGeneratedHook(hook: string): boolean {
  if (/^[A-Za-z0-9+\/=]{16,}$/.test(hook)) return true;

  if (/^[a-z0-9]{10,}_[a-z0-9]{10,}$/i.test(hook)) return true;

  if (/^[a-z]+_[a-z]+_\d{4,}$/i.test(hook)) return true;

  if (/^[A-Za-z0-9]{8,}_[A-Za-z0-9]{8,}$/i.test(hook)) return true;

  return false;
}

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

export function getInstalledPluginHooks(targetPath: string): Map<string, string> {
  const pluginHooks = new Map<string, string>();

  const pluginsDir = path.join(targetPath, 'wp-content', 'plugins');

  if (!fs.existsSync(pluginsDir)) {
    return pluginHooks;
  }

  try {
    const pluginDirs = fs.readdirSync(pluginsDir, { withFileTypes: true });

    for (const dir of pluginDirs) {
      if (!dir.isDirectory()) continue;

      const pluginSlug = dir.name;

      pluginHooks.set(pluginSlug, pluginSlug);
      pluginHooks.set(pluginSlug.replace(/-/g, '_'), pluginSlug);

      const mainFiles = ['index.php', `${pluginSlug}.php`];
      for (const mainFile of mainFiles) {
        const mainPath = path.join(pluginsDir, pluginSlug, mainFile);
        if (fs.existsSync(mainPath)) {
          try {
            const content = fs.readFileSync(mainPath, 'utf-8');
            const hookPattern = /add_(?:action|filter)\s*\([^)]*['"]([^'"]*(?:cron|schedule|scheduled|cronjob)[^'"]*)['"]/gi;
            let hookMatch;
            while ((hookMatch = hookPattern.exec(content)) !== null) {
              const hookName = hookMatch[1];
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

export function classifyCronHook(
  hook: string,
  coreHooks: Set<string>,
  pluginHooks: Map<string, string>,
  activePlugins: string[]
): OrphanedCronEntry {
  if (coreHooks.has(hook)) {
    return {
      hook,
      type: 'unknown',
      severity: 'LOW',
      reason: 'WordPress core cron hook'
    };
  }

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

  if (isRandomGeneratedHook(hook)) {
    return {
      hook,
      type: 'suspicious',
      severity: 'HIGH',
      reason: 'Hook name appears randomly generated or obfuscated'
    };
  }

  return {
    hook,
    type: 'orphaned',
    severity: 'MEDIUM',
    reason: 'No matching plugin or core hook found - may be orphaned from deleted plugin'
  };
}

export function detectOrphanedCronJobs(
  targetPath: string,
  cronOptionValue?: string,
  activePluginsOption?: string[]
): OrphanedCronResult {
  const issues: CronGuardIssue[] = [];

  const coreHooks = getWordPressCoreCronHooks();

  const pluginHooks = getInstalledPluginHooks(targetPath);

  const activePlugins = activePluginsOption || [];

  const cronHooks = cronOptionValue
    ? parseWordPressCronOption(cronOptionValue)
    : [];

  const orphanedJobs: OrphanedCronEntry[] = [];

  for (const hook of cronHooks) {
    const entry = classifyCronHook(hook, coreHooks, pluginHooks, activePlugins);

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
