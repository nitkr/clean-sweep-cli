import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import fetch from 'node-fetch';
import AdmZip from 'adm-zip';
import { createLogger } from '../logger';
import { createThemeBackup } from '../backup';
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

export function registerThemeReinstallCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  program
    .command('theme:reinstall')
    .description('Reinstall an official WordPress.org theme')
    .option('--path <path>', 'WordPress installation path')
    .option('--theme <slug>', 'Theme slug to reinstall (e.g., twentytwentyfour)')
    .option('--dry-run', 'Preview changes without applying them', false)
    .option('--force', 'Actually perform the reinstall', false)
    .option('--backup', 'Create backup before reinstall (default: true)', true)
    .action(async (cmdOptions) => {
      const opts = getOpts();
      let targetPath = path.resolve(cmdOptions.path || opts.path);
      const themeSlug = cmdOptions.theme;
      const dryRun = (cmdOptions.dryRun || opts.dryRun) && !(cmdOptions.force || opts.force);
      const createBackupFlag = cmdOptions.backup !== false;
      const useJson = opts.json || cmdOptions.json;

      const logger = createLogger('info');
      if (useJson) {
        logger.setSilent(true);
      }

      if (!themeSlug) {
        const error = { success: false, error: 'Theme slug is required. Use --theme <slug>' };
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      }

      if (!fs.existsSync(targetPath)) {
        const error = { success: false, error: 'Path does not exist', path: targetPath };
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      }

      const wpResult = detectWordPressRoot(targetPath);
      if (!wpResult.found) {
        const error = { success: false, error: formatWpPathError(wpResult, 'theme:reinstall'), path: targetPath };
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      }
      targetPath = wpResult.path;

      const themesPath = path.join(targetPath, 'wp-content', 'themes');
      const themeDir = path.join(themesPath, themeSlug);
      const themeExists = fs.existsSync(themeDir);

      logger.info(`Downloading ${themeSlug} from wordpress.org`);

      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wp-theme-'));
      const zipPath = path.join(tempDir, 'theme.zip');

      try {
        const downloadUrl = `https://downloads.wordpress.org/theme/${themeSlug}.latest-stable.zip`;
        const response = await fetch(downloadUrl);
        
        if (!response.ok) {
          throw new Error(`Failed to download theme: ${response.status} ${response.statusText}`);
        }

        const buffer = await response.arrayBuffer();
        fs.writeFileSync(zipPath, Buffer.from(buffer));

        const zip = new AdmZip(zipPath);
        const extractDir = path.join(tempDir, 'extracted');
        zip.extractAllTo(extractDir, true);

        const entries = fs.readdirSync(extractDir);
        let extractedThemeDir: string | null = null;
        
        for (const entry of entries) {
          const entryPath = path.join(extractDir, entry);
          const stat = fs.statSync(entryPath);
          if (stat.isDirectory()) {
            extractedThemeDir = entryPath;
            break;
          }
        }

        if (!extractedThemeDir) {
          throw new Error('Invalid theme archive: no theme directory found');
        }

        const result = {
          success: true,
          themeSlug,
          version: 'latest-stable',
          backupPath: null as string | null,
          dryRun,
        };

        if (dryRun) {
          if (!opts.json && !cmdOptions.json) {
            console.log(`\n[DRY RUN] Would reinstall theme: ${themeSlug}`);
            if (themeExists) {
              console.log(`[DRY RUN] Would backup existing theme at: ${themeDir}`);
              console.log(`[DRY RUN] Would remove old theme files`);
            }
            console.log(`[DRY RUN] Would extract new version from: ${downloadUrl}`);
            console.log(`[DRY RUN] Would place theme at: ${themeDir}`);
          }
        } else {
          if (!opts.json && !cmdOptions.json) {
            if (themeExists) {
              if (createBackupFlag) {
                const backupResult = createThemeBackup(themesPath, themeSlug);
                if (backupResult) {
                  result.backupPath = backupResult.backupPath;
                  console.log(`Backup created at: ${backupResult.backupPath}`);
                }
              } else {
                console.log(`Skipping backup (--backup=false)`);
              }
              
              fs.rmSync(themeDir, { recursive: true, force: true });
              console.log(`Removed old theme files`);
            }

            copyDirRecursive(extractedThemeDir, themeDir);
            console.log(`Installed theme: ${themeSlug}`);
          }
        }

        if (opts.json || cmdOptions.json) {
          formatOutput(result, opts.json || cmdOptions.json);
        }
      } catch (err) {
        const error = {
          success: false,
          themeSlug,
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