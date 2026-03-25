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
    .action(async (cmdOptions) => {
      const opts = getOpts();
      let targetPath = path.resolve(cmdOptions.path || opts.path);
      const pluginSlug = cmdOptions.plugin;
      const dryRun = (cmdOptions.dryRun || opts.dryRun) && !(cmdOptions.force || opts.force);
      const createBackupFlag = cmdOptions.backup !== false;
      const useJson = opts.json || cmdOptions.json;

      const logger = createLogger('info');
      if (useJson) {
        logger.setSilent(true);
      }

      if (!pluginSlug) {
        const error = { success: false, error: 'Plugin slug is required. Use --plugin <slug>' };
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      }

      if (!fs.existsSync(targetPath)) {
        const error = { success: false, error: 'Path does not exist', path: targetPath };
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      }

      let wpResult;
      if (!cmdOptions.path && opts.path === process.cwd()) {
        wpResult = detectWordPressRoot(targetPath);
        if (!wpResult.found) {
          const error = { success: false, error: formatWpPathError(wpResult, 'plugin:reinstall'), path: targetPath };
          formatOutput(error, opts.json || cmdOptions.json);
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
          formatOutput(error, opts.json || cmdOptions.json);
          process.exit(1);
        }
      }

      const pluginsPath = path.join(targetPath, 'wp-content', 'plugins');
      const pluginDir = path.join(pluginsPath, pluginSlug);
      const pluginExists = fs.existsSync(pluginDir);

      logger.info(`Downloading ${pluginSlug} from wordpress.org`);

      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wp-plugin-'));
      const zipPath = path.join(tempDir, 'plugin.zip');

      try {
        const downloadUrl = `https://downloads.wordpress.org/plugin/${pluginSlug}.latest-stable.zip`;
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

        const result = {
          success: true,
          pluginSlug,
          version: 'latest-stable',
          backupPath: null as string | null,
          dryRun,
        };

        if (dryRun) {
          if (!opts.json && !cmdOptions.json) {
            console.log(`\n[DRY RUN] Would reinstall plugin: ${pluginSlug}`);
            if (pluginExists) {
              console.log(`[DRY RUN] Would backup existing plugin at: ${pluginDir}`);
              console.log(`[DRY RUN] Would remove old plugin files`);
            }
            console.log(`[DRY RUN] Would extract new version from: ${downloadUrl}`);
            console.log(`[DRY RUN] Would place plugin at: ${pluginDir}`);
          }
        } else {
          if (!opts.json && !cmdOptions.json) {
            if (pluginExists) {
              if (createBackupFlag) {
                const backupResult = createPluginBackup(pluginsPath, pluginSlug);
                if (backupResult) {
                  result.backupPath = backupResult.backupPath;
                  console.log(`Backup created at: ${backupResult.backupPath}`);
                }
              } else {
                console.log(`Skipping backup (--backup=false)`);
              }
              
              fs.rmSync(pluginDir, { recursive: true, force: true });
              console.log(`Removed old plugin files`);
            }

            copyDirRecursive(extractedPluginDir, pluginDir);
            console.log(`Installed plugin: ${pluginSlug}`);
          }
        }

        if (opts.json || cmdOptions.json) {
          formatOutput(result, opts.json || cmdOptions.json);
        }
      } catch (err) {
        const error = {
          success: false,
          pluginSlug,
          error: String(err),
          dryRun,
        };
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });
}
