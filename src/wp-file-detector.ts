import * as path from 'path';
import * as fs from 'fs';
import fg from 'fast-glob';

export interface UnknownFilesResult {
  count: number;
  files: string[];
}

const WP_CORE_PATTERNS = [
  'wp-admin/**',
  'wp-includes/**',
  'wp-*.php',
  'index.php',
  'xmlrpc.php',
];

const WP_ROOT_FILES = [
  'wp-login.php',
  'wp-config.php',
  'wp-settings.php',
  'wp-load.php',
  'wp-blog-header.php',
  'wp-cron.php',
  'wp-links-opml.php',
  'wp-trackback.php',
  'xmlrpc.php',
  'wp-app.php',
  'wp-cron.php',
  'readme.html',
  'license.txt',
  'install.php',
];

function isWordPressCoreFile(relativePath: string): boolean {
  const normalized = relativePath.replace(/\\/g, '/');
  
  if (normalized.startsWith('wp-admin/') || normalized.startsWith('wp-includes/')) {
    return true;
  }

  for (const pattern of WP_CORE_PATTERNS) {
    if (pattern === 'wp-*.php') {
      if (normalized.match(/^wp-.*\.php$/)) {
        return true;
      }
    } else if (normalized === pattern || normalized === pattern.replace(/\*\*/g, '')) {
      return true;
    }
  }

  return false;
}

export async function findUnknownFiles(
  targetPath: string,
  ignorePatterns: string[] = ['**/node_modules/**', '**/dist/**', '**/.git/**', '**/wp-content/**']
): Promise<UnknownFilesResult> {
  const allFiles = await fg('**/*', {
    cwd: targetPath,
    onlyFiles: true,
    absolute: true,
    ignore: ignorePatterns,
  });

  const unknownFiles: string[] = [];

  for (const file of allFiles) {
    const relativePath = path.relative(targetPath, file);

    if (!isWordPressCoreFile(relativePath)) {
      unknownFiles.push(relativePath);
    }
  }

  return {
    count: unknownFiles.length,
    files: unknownFiles.sort(),
  };
}

export function isWordPressInstallation(targetPath: string): boolean {
  const requiredDirs = ['wp-admin', 'wp-includes'];
  const requiredFiles = ['wp-config.php', 'wp-login.php'];

  for (const dir of requiredDirs) {
    if (!fs.existsSync(path.join(targetPath, dir))) {
      return false;
    }
  }

  for (const file of requiredFiles) {
    if (!fs.existsSync(path.join(targetPath, file))) {
      return false;
    }
  }

  return true;
}