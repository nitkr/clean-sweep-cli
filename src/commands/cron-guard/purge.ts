import { exec } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { CronPurgeResult } from './types';
import { getWordPressCoreCronHooks, getInstalledPluginHooks, classifyCronHook } from './orphaned';

export { CronPurgeResult };

function extractCronEntries(cronValue: string): Map<string, string> {
  const entries = new Map<string, string>();

  const entryPattern = /s:(\d+):"([^"]+)";a:(\d+):\{/g;

  let match;
  while ((match = entryPattern.exec(cronValue)) !== null) {
    const [, keyLen, hookName, arrLen] = match;
    const keyLength = parseInt(keyLen, 10);

    if (keyLength !== hookName.length) {
      continue;
    }

    const startPos = match.index;
    const openingBraces = 1;
    let endPos = match.index + match[0].length;
    let braceCount = openingBraces;

    while (braceCount > 0 && endPos < cronValue.length) {
      if (cronValue[endPos] === '{') braceCount++;
      else if (cronValue[endPos] === '}') braceCount--;
      endPos++;
    }

    const fullEntry = cronValue.substring(startPos, endPos);
    entries.set(hookName, fullEntry);
  }

  return entries;
}

function rebuildCronArray(entries: Map<string, string>): string {
  const hooks = Array.from(entries.keys());
  let result = `a:${hooks.length}:{`;

  for (const hook of hooks) {
    result += entries.get(hook) || '';
  }

  result += '}';
  return result;
}

async function runMysqlQuery(
  host: string,
  user: string,
  pass: string,
  dbName: string,
  query: string
): Promise<string> {
  return new Promise((resolve, reject) => {
    const cmd = `mysql -h "${host}" -u "${user}"${pass ? ` -p"${pass}"` : ''} "${dbName}" -e "${query.replace(/"/g, '\\"')}" -B 2>/dev/null`;

    exec(cmd, { timeout: 30000 }, (error, stdout, stderr) => {
      if (error) {
        reject(error);
      } else {
        resolve(stdout);
      }
    });
  });
}

function parseWpConfigForCron(targetPath: string): { host: string; user: string; pass: string; name: string; prefix: string } | null {
  const wpConfigPath = path.join(targetPath, 'wp-config.php');

  if (!fs.existsSync(wpConfigPath)) {
    return null;
  }

  const content = fs.readFileSync(wpConfigPath, 'utf-8');

  const extractConstant = (name: string): string | null => {
    const regex = new RegExp(`define\\s*\\(\\s*['"]${name}['"]\\s*,\\s*['"]([^'"]*)['"]\\s*\\)`, 'i');
    const match = content.match(regex);
    return match ? match[1] : null;
  };

  const extractPrefix = (): string => {
    const regex = /\$table_prefix\s*=\s*['"]([^'"]*)['"]/;
    const match = content.match(regex);
    return match ? match[1] : 'wp_';
  };

  const host = extractConstant('DB_HOST') || 'localhost';
  const name = extractConstant('DB_NAME');
  const user = extractConstant('DB_USER');
  const pass = extractConstant('DB_PASSWORD');
  const prefix = extractPrefix();

  if (!name || !user) {
    return null;
  }

  return { host, name, user, pass: pass || '', prefix };
}

export async function purgeOrphanedCronJobs(
  targetPath: string,
  options: {
    dryRun?: boolean;
    excludeHooks?: string[];
    onlySuspicious?: boolean;
  } = {}
): Promise<CronPurgeResult> {
  const { dryRun = false, excludeHooks = [], onlySuspicious = false } = options;

  const dbConfig = parseWpConfigForCron(targetPath);
  if (!dbConfig) {
    return {
      success: false,
      totalHooks: 0,
      hooksDeleted: 0,
      hooksPreserved: 0,
      deletedHooks: [],
      preservedHooks: [],
      backupCreated: false,
      message: 'Could not parse wp-config.php for database credentials'
    };
  }

  const { host, user, pass, name, prefix } = dbConfig;

  let cronValue: string;
  try {
    const query = `SELECT option_value FROM ${prefix}options WHERE option_name = 'cron' LIMIT 1`;
    const result = await runMysqlQuery(host, user, pass, name, query);

    const lines = result.trim().split('\n');
    if (lines.length < 2) {
      return {
        success: true,
        totalHooks: 0,
        hooksDeleted: 0,
        hooksPreserved: 0,
        deletedHooks: [],
        preservedHooks: [],
        backupCreated: false,
        message: 'No cron option found in database'
      };
    }
    cronValue = lines[1];
  } catch (error) {
    return {
      success: false,
      totalHooks: 0,
      hooksDeleted: 0,
      hooksPreserved: 0,
      deletedHooks: [],
      preservedHooks: [],
      backupCreated: false,
      message: `Failed to read cron option: ${error}`
    };
  }

  const entries = extractCronEntries(cronValue);
  const allHooks = Array.from(entries.keys());

  if (allHooks.length === 0) {
    return {
      success: true,
      totalHooks: 0,
      hooksDeleted: 0,
      hooksPreserved: 0,
      deletedHooks: [],
      preservedHooks: [],
      backupCreated: false,
      message: 'No cron hooks found'
    };
  }

  const coreHooks = getWordPressCoreCronHooks();
  const pluginHooks = getInstalledPluginHooks(targetPath);

  const hooksToDelete: string[] = [];
  const hooksToPreserve: string[] = [];

  for (const hook of allHooks) {
    if (excludeHooks.includes(hook)) {
      hooksToPreserve.push(hook);
      continue;
    }

    const entry = classifyCronHook(hook, coreHooks, pluginHooks, []);

    let shouldDelete = false;

    if (onlySuspicious) {
      shouldDelete = entry.type === 'suspicious' || entry.type === 'malicious';
    } else {
      shouldDelete = entry.type === 'orphaned' || entry.type === 'suspicious' || entry.type === 'malicious';
    }

    if (shouldDelete) {
      hooksToDelete.push(hook);
    } else {
      hooksToPreserve.push(hook);
    }
  }

  if (dryRun) {
    return {
      success: true,
      totalHooks: allHooks.length,
      hooksDeleted: hooksToDelete.length,
      hooksPreserved: hooksToPreserve.length,
      deletedHooks: hooksToDelete,
      preservedHooks: hooksToPreserve,
      backupCreated: false,
      message: `[DRY RUN] Would delete ${hooksToDelete.length} of ${allHooks.length} cron hooks`
    };
  }

  const backupDir = path.join(targetPath, 'clean-sweep-cli', 'quarantine-backup');
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupFile = path.join(backupDir, `cron-backup-${timestamp}.txt`);

  try {
    if (!fs.existsSync(backupDir)) {
      fs.mkdirSync(backupDir, { recursive: true });
    }
    fs.writeFileSync(backupFile, cronValue, 'utf-8');
  } catch (error) {
    return {
      success: false,
      totalHooks: allHooks.length,
      hooksDeleted: 0,
      hooksPreserved: allHooks.length,
      deletedHooks: [],
      preservedHooks: allHooks,
      backupCreated: false,
      message: `Failed to create backup: ${error}`
    };
  }

  const newEntries = new Map<string, string>();
  for (const hook of hooksToPreserve) {
    const entry = entries.get(hook);
    if (entry) {
      newEntries.set(hook, entry);
    }
  }

  const newCronValue = rebuildCronArray(newEntries);

  const escapedValue = newCronValue.replace(/'/g, "''");

  try {
    const updateQuery = `UPDATE ${prefix}options SET option_value = '${escapedValue}' WHERE option_name = 'cron'`;
    await runMysqlQuery(host, user, pass, name, updateQuery);
  } catch (error) {
    return {
      success: false,
      totalHooks: allHooks.length,
      hooksDeleted: 0,
      hooksPreserved: allHooks.length,
      deletedHooks: [],
      preservedHooks: allHooks,
      backupCreated: true,
      message: `Failed to update cron option: ${error}. Backup saved to ${backupFile}`
    };
  }

  return {
    success: true,
    totalHooks: allHooks.length,
    hooksDeleted: hooksToDelete.length,
    hooksPreserved: hooksToPreserve.length,
    deletedHooks: hooksToDelete,
    preservedHooks: hooksToPreserve,
    backupCreated: true,
    message: `Successfully purged ${hooksToDelete.length} cron hooks. Backup saved to ${backupFile}`
  };
}
