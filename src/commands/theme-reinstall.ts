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

async function reinstallTheme(
  themeSlug: string,
  themeDir: string,
  themesPath: string,
  createBackupFlag: boolean,
  verbose: boolean
): Promise<{ success: boolean; error?: string }> {
  const downloadUrl = `https://downloads.wordpress.org/theme/${themeSlug}.latest-stable.zip`;

  if (verbose) {
    console.log(`Processing theme: ${themeSlug}`);
    console.log(`Downloading ${themeSlug} from wordpress.org`);
  }

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wp-theme-'));
  const zipPath = path.join(tempDir, 'theme.zip');

  try {
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

    const themeExists = fs.existsSync(themeDir);

    if (themeExists) {
      if (createBackupFlag) {
        const backupResult = createThemeBackup(themesPath, themeSlug);
        if (backupResult && verbose) {
          console.log(`Backup created at: ${backupResult.backupPath}`);
        }
      }

      fs.rmSync(themeDir, { recursive: true, force: true });
      if (verbose) {
        console.log(`Removed old theme files`);
      }
    }

    copyDirRecursive(extractedThemeDir, themeDir);

    if (verbose) {
      console.log(`Successfully reinstalled ${themeSlug}`);
    }

    return { success: true };
  } catch (err) {
    const errorMessage = String(err);
    if (verbose) {
      console.log(`Failed to reinstall ${themeSlug}: ${errorMessage}`);
    }
    return { success: false, error: errorMessage };
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
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
    .option('--verbose', 'Show detailed progress')
    .action(async (cmdOptions) => {
      const opts = getOpts();
      let targetPath = path.resolve(cmdOptions.path || opts.path);
      const themeSlug = cmdOptions.theme;
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
          const error = { success: false, error: formatWpPathError(wpResult, 'theme:reinstall'), path: targetPath };
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
          const error = { success: false, error: formatWpPathError(wpResult, 'theme:reinstall'), path: targetPath };
          formatOutput(error, useJson);
          process.exit(1);
        }
      }

      const themesPath = path.join(targetPath, 'wp-content', 'themes');

      if (!themeSlug) {
        if (!fs.existsSync(themesPath)) {
          const error = { success: false, error: 'Themes directory does not exist', path: themesPath };
          formatOutput(error, useJson);
          process.exit(1);
        }

        const entries = fs.readdirSync(themesPath);
        const themeSlugs = entries.filter((entry) => {
          const entryPath = path.join(themesPath, entry);
          const stat = fs.statSync(entryPath);
          return stat.isDirectory() && entry !== '.';
        });

        if (themeSlugs.length === 0) {
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
            console.log(`\n[DRY RUN] Would reinstall all themes: ${themeSlugs.join(', ')}`);
          }
          return;
        }

        const reinstalled: string[] = [];
        const failed: { slug: string; error: string }[] = [];

        for (const slug of themeSlugs) {
          const themeDir = path.join(themesPath, slug);
          const result = await reinstallTheme(slug, themeDir, themesPath, createBackupFlag, verbose);
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
          console.log('\nThemes that could not be re-installed:');
          for (const { slug, error } of failed) {
            console.log(`  - ${slug}: ${error}`);
          }
          process.exit(1);
        }
        return;
      }

      const themeDir = path.join(themesPath, themeSlug);
      const downloadUrl = `https://downloads.wordpress.org/theme/${themeSlug}.latest-stable.zip`;

      if (dryRun) {
        const themeExists = fs.existsSync(themeDir);
        const result = {
          success: true,
          themeSlug,
          dryRun: true,
        };
        formatOutput(result, useJson);
        if (!useJson) {
          console.log(`\n[DRY RUN] Would reinstall theme: ${themeSlug}`);
          if (themeExists) {
            console.log(`[DRY RUN] Would backup existing theme at: ${themeDir}`);
            console.log(`[DRY RUN] Would remove old theme files`);
          }
          console.log(`[DRY RUN] Would download new version from: ${downloadUrl}`);
          console.log(`[DRY RUN] Would place theme at: ${themeDir}`);
        }
        return;
      }

      const result = await reinstallTheme(themeSlug, themeDir, themesPath, createBackupFlag, verbose);

      if (!result.success) {
        const error = {
          success: false,
          error: result.error || 'Unknown error',
          themeSlug,
        };
        formatOutput(error, useJson);
        process.exit(1);
      }

      const successResult: ReinstallResult = {
        success: true,
        reinstalled: [themeSlug],
        failed: [],
      };
      formatOutput(successResult, useJson);
    });
}
