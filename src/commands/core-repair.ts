import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import fetch from 'node-fetch';
import * as tar from 'tar';
import { createLogger, getLogger, LogLevel } from '../logger';
import { createBackup, CoreRepairResult } from '../backup';
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

export function registerCoreRepairCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  program
    .command('core:repair')
    .description('Repair WordPress core files by replacing with fresh download')
    .option('--path <path>', 'WordPress installation path')
    .option('--dry-run', 'Preview changes without applying them', false)
    .option('--force', 'Actually perform the replacement', false)
    .option('--backup', 'Create backup before repair (default: true)', true)
    .option('--version <version>', 'Specific WordPress version to install (e.g., 6.4.2)')
    .action(async (cmdOptions) => {
      const opts = getOpts();
      let targetPath = path.resolve(cmdOptions.path || opts.path);
      const dryRun = (cmdOptions.dryRun || opts.dryRun) && !(cmdOptions.force || opts.force);
      const useJson = opts.json || cmdOptions.json;

      const logger = createLogger('info');
      if (useJson) {
        logger.setSilent(true);
      }

      if (!fs.existsSync(targetPath)) {
        const error = { success: false, error: 'Path does not exist', path: targetPath };
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      }

      let wpResult;
      if (!cmdOptions.path && opts.path === process.cwd()) {
        wpResult = detectWordPressRoot(targetPath);
        if (wpResult.found) {
          targetPath = wpResult.path;
        }
      } else {
        const stats = fs.statSync(targetPath);
        if (!stats.isDirectory()) {
          const error = { success: false, error: 'Path is not a directory', path: targetPath };
          formatOutput(error, opts.json || cmdOptions.json);
          process.exit(1);
        }
        const wpConfigPath = path.join(targetPath, 'wp-config.php');
        if (fs.existsSync(wpConfigPath)) {
          wpResult = { path: targetPath, found: true, searchedPaths: [targetPath] };
        } else {
          wpResult = { path: targetPath, found: false, searchedPaths: [targetPath] };
        }
      }

      if (!wpResult.found) {
        const error = { success: false, error: formatWpPathError(wpResult, 'core:repair'), path: targetPath };
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      }
      targetPath = wpResult.path;

      const wpConfigPath = path.join(targetPath, 'wp-config.php');
      const wpContentPath = path.join(targetPath, 'wp-content');
      const htaccessPath = path.join(targetPath, '.htaccess');
      const robotsTxtPath = path.join(targetPath, 'robots.txt');

      const preserveList: string[] = [];
      if (fs.existsSync(wpConfigPath)) preserveList.push('wp-config.php');
      if (fs.existsSync(wpContentPath)) preserveList.push('wp-content');
      if (fs.existsSync(htaccessPath)) preserveList.push('.htaccess');
      if (fs.existsSync(robotsTxtPath)) preserveList.push('robots.txt');

      const version = cmdOptions.version;
      const createBackupFlag = cmdOptions.backup !== false;

      const standardCoreFiles = [
        'wp-admin', 'wp-includes', 'index.php', 'wp-login.php', 'wp-blog-header.php',
        'wp-comments-post.php', 'wp-cron.php', 'wp-links-opml.php', 'wp-load.php',
        'wp-mail.php', 'wp-settings.php', 'wp-signup.php', 'wp-trackback.php',
        'xmlrpc.php', 'wp-activate.php', 'wp-config-sample.php', 'readme.html',
        'license.txt', '.wp-cron.php', 'error_log',
      ];

      if (dryRun) {
        const result: CoreRepairResult = {
          success: true,
          filesReplaced: standardCoreFiles,
          filesPreserved: preserveList,
          backupPath: null,
          dryRun: true,
        };

        if (!opts.json && !cmdOptions.json) {
          console.log('\n[DRY RUN] Would replace core files (standard WordPress core file list):');
          for (const file of standardCoreFiles) {
            console.log(`  - ${file}`);
          }
          console.log(`\n[DRY RUN] Would preserve ${preserveList.length} file(s)/dir(s):`);
          for (const file of preserveList) {
            console.log(`  - ${file}`);
          }
        }

        if (opts.json || cmdOptions.json) {
          formatOutput(result, opts.json || cmdOptions.json);
        }
        return;
      }

      const downloadUrl = version
        ? `https://wordpress.org/wordpress-${version}.tar.gz`
        : 'https://wordpress.org/latest.tar.gz';

      logger.info(`Downloading WordPress${version ? ` ${version}` : ' latest'} from wordpress.org`);

      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wp-core-'));
      const zipPath = path.join(tempDir, 'wordpress.tar.gz');

      try {
        const response = await fetch(downloadUrl);
        if (!response.ok) {
          throw new Error(`Failed to download: ${response.status} ${response.statusText}`);
        }

        const buffer = await response.arrayBuffer();
        fs.writeFileSync(zipPath, Buffer.from(buffer));

        const extractDir = path.join(tempDir, 'extracted');
        fs.mkdirSync(extractDir, { recursive: true });
        await tar.extract({ file: zipPath, cwd: extractDir });

        const wordpressDir = path.join(extractDir, 'wordpress');
        if (!fs.existsSync(wordpressDir)) {
          throw new Error('Invalid WordPress archive: wordpress directory not found');
        }

        const newFiles = fs.readdirSync(wordpressDir);
        const filesToReplace: string[] = [];
        const filesToPreserve: string[] = [...preserveList];

        for (const file of newFiles) {
          if (preserveList.includes(file)) {
            continue;
          }
          filesToReplace.push(file);
        }

        const result: CoreRepairResult = {
          success: true,
          filesReplaced: filesToReplace,
          filesPreserved: filesToPreserve,
          backupPath: null,
          dryRun,
        };

        if (!opts.json && !cmdOptions.json) {
          if (createBackupFlag) {
            const backupResult = createBackup(targetPath);
            result.backupPath = backupResult.backupPath;
            console.log(`Backup created at: ${backupResult.backupPath}`);
          } else {
            console.log(`Skipping backup (--backup=false)`);
          }

          for (const file of filesToReplace) {
            const srcPath = path.join(wordpressDir, file);
            const destPath = path.join(targetPath, file);

            if (fs.existsSync(srcPath)) {
              const stat = fs.statSync(srcPath);
              if (stat.isDirectory()) {
                if (fs.existsSync(destPath)) {
                  fs.rmSync(destPath, { recursive: true });
                }
                copyDirRecursive(srcPath, destPath);
              } else {
                fs.copyFileSync(srcPath, destPath);
              }
            }
          }
          console.log(`Replaced ${filesToReplace.length} core file(s)`);
        }

        if (opts.json || cmdOptions.json) {
          formatOutput(result, opts.json || cmdOptions.json);
        }
      } catch (err) {
        const error = {
          success: false,
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
