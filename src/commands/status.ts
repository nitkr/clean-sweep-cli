import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import { detectWordPressRoot, formatWpPathError } from '../wp-path-detector';

interface CliOptions {
  dryRun: boolean;
  force: boolean;
  json: boolean;
  path: string;
  verbose: boolean;
}

interface StatusResult {
  version: string | null;
  pluginsCount: number;
  themesCount: number;
  dbConnected: boolean;
  wpContentWritable: boolean;
  lastCoreUpdate: string | null;
  dryRun: boolean;
}

function formatOutput(data: unknown, useJson: boolean): void {
  if (useJson) {
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(data);
  }
}

export function getWpVersion(wpPath: string): string | null {
  const versionFile = path.join(wpPath, 'wp-includes', 'version.php');
  if (!fs.existsSync(versionFile)) {
    return null;
  }

  try {
    const content = fs.readFileSync(versionFile, 'utf-8');
    const match = content.match(/\$wp_version\s*=\s*['"]([^'"]+)['"]/);
    return match ? match[1] : null;
  } catch {
    return null;
  }
}

export function getPluginsCount(wpPath: string): number {
  const pluginsDir = path.join(wpPath, 'wp-content', 'plugins');
  if (!fs.existsSync(pluginsDir)) {
    return 0;
  }

  try {
    const entries = fs.readdirSync(pluginsDir, { withFileTypes: true });
    return entries.filter(e => e.isDirectory()).length;
  } catch {
    return 0;
  }
}

export function getThemesCount(wpPath: string): number {
  const themesDir = path.join(wpPath, 'wp-content', 'themes');
  if (!fs.existsSync(themesDir)) {
    return 0;
  }

  try {
    const entries = fs.readdirSync(themesDir, { withFileTypes: true });
    return entries.filter(e => e.isDirectory()).length;
  } catch {
    return 0;
  }
}

export function checkWpContentWritable(wpPath: string): boolean {
  const wpContentDir = path.join(wpPath, 'wp-content');
  if (!fs.existsSync(wpContentDir)) {
    return false;
  }

  try {
    const testFile = path.join(wpContentDir, '.write-test-' + Date.now());
    fs.writeFileSync(testFile, '');
    fs.unlinkSync(testFile);
    return true;
  } catch {
    return false;
  }
}

export function checkDbConnection(wpPath: string): boolean {
  const wpConfig = path.join(wpPath, 'wp-config.php');
  if (!fs.existsSync(wpConfig)) {
    return false;
  }

  try {
    const content = fs.readFileSync(wpConfig, 'utf-8');
    const dbNameMatch = content.match(/define\s*\(\s*['"]DB_NAME['"]\s*,\s*['"]([^'"]+)['"]/);
    const dbUserMatch = content.match(/define\s*\(\s*['"]DB_USER['"]\s*,\s*['"]([^'"]+)['"]/);
    const dbHostMatch = content.match(/define\s*\(\s*['"]DB_HOST['"]\s*,\s*['"]([^'"]+)['"]/);

    if (!dbNameMatch || !dbUserMatch) {
      return false;
    }

    const dbName = dbNameMatch[1];
    const dbUser = dbUserMatch[1];
    const dbHost = dbHostMatch ? dbHostMatch[1] : 'localhost';

    return dbName.length > 0 && dbUser.length > 0;
  } catch {
    return false;
  }
}

export function getLastCoreUpdate(wpPath: string): string | null {
  const wpDir = path.join(wpPath, 'wp-admin', 'includes', 'update.php');
  if (!fs.existsSync(wpDir)) {
    return null;
  }

  const optionDb = path.join(wpPath, 'wp-includes', 'option.php');
  if (!fs.existsSync(optionDb)) {
    return null;
  }

  try {
    const content = fs.readFileSync(optionDb, 'utf-8');
    // Match $option['last_update_check'] or $options['last_update_check'] = 'timestamp';
    const match = content.match(/\$options?\['last_update_check'\]\s*=\s*['"]([^'"]+)['"]/);
    if (match && match[1]) {
      const date = new Date(match[1]);
      return isNaN(date.getTime()) ? null : date.toISOString();
    }
    return null;
  } catch {
    return null;
  }
}

export function registerStatusCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  program
    .command('status')
    .description('Show WordPress installation health status')
    .option('--path <path>', 'WordPress installation path')
    .option('--json', 'Output results as JSON', false)
    .action(async (cmdOptions) => {
      const opts = getOpts();
      let targetPath = path.resolve(cmdOptions.path || opts.path);
      const useJson = opts.json || cmdOptions.json;

      if (!fs.existsSync(targetPath)) {
        const error = { error: 'Path does not exist', path: targetPath };
        formatOutput(error, useJson);
        process.exit(1);
      }

      const stats = fs.statSync(targetPath);
      if (!stats.isDirectory()) {
        const error = { error: 'Path is not a directory', path: targetPath };
        formatOutput(error, useJson);
        process.exit(1);
      }

      const wpResult = detectWordPressRoot(targetPath);
      if (!wpResult.found) {
        const error = { error: formatWpPathError(wpResult, 'status'), path: targetPath };
        formatOutput(error, useJson);
        process.exit(1);
      }
      targetPath = wpResult.path;

      const result: StatusResult = {
        version: getWpVersion(targetPath),
        pluginsCount: getPluginsCount(targetPath),
        themesCount: getThemesCount(targetPath),
        dbConnected: checkDbConnection(targetPath),
        wpContentWritable: checkWpContentWritable(targetPath),
        lastCoreUpdate: getLastCoreUpdate(targetPath),
        dryRun: opts.dryRun,
      };

      if (useJson) {
        formatOutput(result, useJson);
      } else {
        console.log('WordPress Status:');
        console.log(`  Version: ${result.version || 'Unknown'}`);
        console.log(`  Plugins: ${result.pluginsCount}`);
        console.log(`  Themes: ${result.themesCount}`);
        console.log(`  Database: ${result.dbConnected ? 'Connected' : 'Not connected'}`);
        console.log(`  wp-content writable: ${result.wpContentWritable ? 'Yes' : 'No'}`);
        console.log(`  Last core update check: ${result.lastCoreUpdate || 'Unknown'}`);
      }
    });
}
