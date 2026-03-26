import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import fetch from 'node-fetch';
import AdmZip from 'adm-zip';
import { createLogger } from '../logger';
import { createPluginBackup } from '../backup';
import { detectWordPressRoot, formatWpPathError } from '../wp-path-detector';

interface CliOptions {
  dryRun: boolean;
  force: boolean;
  json: boolean;
  path: string;
  verbose: boolean;
}

interface ReinstallResult {
  success: boolean;
  reinstalled: string[];
  failed: { slug: string; error: string }[];
}

function formatOutput(data: unknown, useJson: boolean): void {
  if (useJson) {
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(data);
  }
}

function copyDirRecursive(src: string, dest: string): void {
  fs.mkdirSync(dest, { recursive: true });
  const entries = fs.readdirSync(src);
  for (const entry of entries) {
    const srcPath = path.join(src, entry);
    const destPath = path.join(dest, entry);
    const stat = fs.statSync(srcPath);
    if (stat.isDirectory()) {
      copyDirRecursive(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

async function reinstallPlugin(
  pluginSlug: string,
  pluginDir: string,
  pluginsPath: string,
  createBackupFlag: boolean,
  verbose: boolean
): Promise<{ success: boolean; error?: string }> {
  const downloadUrl = `https://downloads.wordpress.org/plugin/${pluginSlug}.latest-stable.zip`;

  if (verbose) {
    console.log(`Processing plugin: ${pluginSlug}`);
    console.log(`Downloading ${pluginSlug} from wordpress.org`);
  }

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wp-plugin-'));
  const zipPath = path.join(tempDir, 'plugin.zip');

  try {
    const response = await fetch(downloadUrl);

    if (!response.ok) {
      throw new Error(`Failed to download plugin: ${response.status} ${response.statusText}`);
    }

    const buffer = await response.arrayBuffer();
    fs.writeFileSync(zipPath, Buffer.from(buffer));

    const zip = new AdmZip(zipPath);
    const extractDir = path.join(tempDir, 'extracted');
    zip.extractAllTo(extractDir, true);

    const entries = fs.readdirSync(extractDir);
    let extractedPluginDir: string | null = null;

    for (const entry of entries) {
      const entryPath = path.join(extractDir, entry);
      const stat = fs.statSync(entryPath);
      if (stat.isDirectory()) {
        extractedPluginDir = entryPath;
        break;
      }
    }

    if (!extractedPluginDir) {
      throw new Error('Invalid plugin archive: no plugin directory found');
    }

    const pluginExists = fs.existsSync(pluginDir);

    if (pluginExists) {
      if (createBackupFlag) {
        const backupResult = createPluginBackup(pluginsPath, pluginSlug);
        if (backupResult && verbose) {
          console.log(`Backup created at: ${backupResult.backupPath}`);
        }
      }

      fs.rmSync(pluginDir, { recursive: true, force: true });
      if (verbose) {
        console.log(`Removed old plugin files`);
      }
    }

    copyDirRecursive(extractedPluginDir, pluginDir);

    if (verbose) {
      console.log(`Successfully reinstalled ${pluginSlug}`);
    }

    return { success: true };
  } catch (err) {
    const errorMessage = String(err);
    if (verbose) {
      console.log(`Failed to reinstall ${pluginSlug}: ${errorMessage}`);
    }
    return { success: false, error: errorMessage };
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

export function registerPluginReinstallCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  program
    .command('plugin:reinstall')
    .description('Reinstall an official WordPress.org plugin')
    .option('--path <path>', 'WordPress installation path')
    .option('--plugin <slug>', 'Plugin slug to reinstall (e.g., akismet, wordpress-seo)')
    .option('--dry-run', 'Preview changes without applying them', false)
    .option('--force', 'Actually perform the reinstall', false)
    .option('--backup', 'Create backup before reinstall (default: true)', true)
    .option('--verbose', 'Show detailed progress')
    .action(async (cmdOptions) => {
      const opts = getOpts();
      let targetPath = path.resolve(cmdOptions.path || opts.path);
      const pluginSlug = cmdOptions.plugin;
      const dryRun = (cmdOptions.dryRun || opts.dryRun) && !(cmdOptions.force || opts.force);
      const createBackupFlag = cmdOptions.backup !== false;
      const useJson = opts.json || cmdOptions.json;
      const verbose = opts.verbose || cmdOptions.verbose;

      const logger = createLogger('info');
      if (useJson) {
        logger.setSilent(true);
      }

      if (!fs.existsSync(targetPath)) {
        const error = { success: false, error: 'Path does not exist', path: targetPath };
        formatOutput(error, useJson);
        process.exit(1);
      }

      let wpResult;
      if (!cmdOptions.path && opts.path === process.cwd()) {
        wpResult = detectWordPressRoot(targetPath);
        if (!wpResult.found) {
          const error = { success: false, error: formatWpPathError(wpResult, 'plugin:reinstall'), path: targetPath };
          formatOutput(error, useJson);
          process.exit(1);
        }
        targetPath = wpResult.path;
      } else {
        const wpConfigPath = path.join(targetPath, 'wp-config.php');
        if (fs.existsSync(wpConfigPath)) {
          wpResult = { path: targetPath, found: true, searchedPaths: [targetPath] };
        } else {
          wpResult = { path: targetPath, found: false, searchedPaths: [targetPath] };
          const error = { success: false, error: formatWpPathError(wpResult, 'plugin:reinstall'), path: targetPath };
          formatOutput(error, useJson);
          process.exit(1);
        }
      }

      const pluginsPath = path.join(targetPath, 'wp-content', 'plugins');

      if (!pluginSlug) {
        if (!fs.existsSync(pluginsPath)) {
          const error = { success: false, error: 'Plugins directory does not exist', path: pluginsPath };
          formatOutput(error, useJson);
          process.exit(1);
        }

        const entries = fs.readdirSync(pluginsPath);
        const pluginSlugs = entries.filter((entry) => {
          const entryPath = path.join(pluginsPath, entry);
          const stat = fs.statSync(entryPath);
          return stat.isDirectory() && entry !== '.';
        });

        if (pluginSlugs.length === 0) {
          const result: ReinstallResult = {
            success: true,
            reinstalled: [],
            failed: [],
          };
          formatOutput(result, useJson);
          return;
        }

        if (dryRun) {
          const result: ReinstallResult = {
            success: true,
            reinstalled: [],
            failed: [],
          };
          formatOutput(result, useJson);
          if (!useJson) {
            console.log(`\n[DRY RUN] Would reinstall all plugins: ${pluginSlugs.join(', ')}`);
          }
          return;
        }

        const reinstalled: string[] = [];
        const failed: { slug: string; error: string }[] = [];

        for (const slug of pluginSlugs) {
          const pluginDir = path.join(pluginsPath, slug);
          const result = await reinstallPlugin(slug, pluginDir, pluginsPath, createBackupFlag, verbose);
          if (result.success) {
            reinstalled.push(slug);
          } else {
            failed.push({ slug, error: result.error || 'Unknown error' });
          }
        }

        const finalResult: ReinstallResult = {
          success: failed.length === 0,
          reinstalled,
          failed,
        };

        formatOutput(finalResult, useJson);

        if (failed.length > 0) {
          console.log('\nPlugins that could not be re-installed:');
          for (const { slug, error } of failed) {
            console.log(`  - ${slug}: ${error}`);
          }
          process.exit(1);
        }
        return;
      }

      const pluginDir = path.join(pluginsPath, pluginSlug);
      const downloadUrl = `https://downloads.wordpress.org/plugin/${pluginSlug}.latest-stable.zip`;

      if (dryRun) {
        const pluginExists = fs.existsSync(pluginDir);
        const result = {
          success: true,
          pluginSlug,
          dryRun: true,
        };
        formatOutput(result, useJson);
        if (!useJson) {
          console.log(`\n[DRY RUN] Would reinstall plugin: ${pluginSlug}`);
          if (pluginExists) {
            console.log(`[DRY RUN] Would backup existing plugin at: ${pluginDir}`);
            console.log(`[DRY RUN] Would remove old plugin files`);
          }
          console.log(`[DRY RUN] Would download new version from: ${downloadUrl}`);
          console.log(`[DRY RUN] Would place plugin at: ${pluginDir}`);
        }
        return;
      }

      const result = await reinstallPlugin(pluginSlug, pluginDir, pluginsPath, createBackupFlag, verbose);

      if (!result.success) {
        const error = {
          success: false,
          error: result.error || 'Unknown error',
          pluginSlug,
        };
        formatOutput(error, useJson);
        process.exit(1);
      }

      const successResult = {
        success: true,
        reinstalled: [pluginSlug],
        failed: [],
      };
      formatOutput(successResult, useJson);
    });
}
