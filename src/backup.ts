import * as fs from 'fs';
import * as path from 'path';
import AdmZip from 'adm-zip';

export interface BackupResult {
  success: boolean;
  backupPath: string;
  filesBackedUp: number;
}

function countFilesRecursive(dirPath: string): number {
  let count = 0;
  if (!fs.existsSync(dirPath)) return count;
  
  const entries = fs.readdirSync(dirPath);
  for (const entry of entries) {
    const entryPath = path.join(dirPath, entry);
    const stat = fs.statSync(entryPath);
    if (stat.isDirectory()) {
      count += countFilesRecursive(entryPath);
    } else {
      count++;
    }
  }
  return count;
}

export function createBackup(targetPath: string): BackupResult {
  if (!fs.existsSync(targetPath)) {
    throw new Error(`Target path does not exist: ${targetPath}`);
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupDir = path.join(targetPath, 'clean-sweep-cli', 'backups');
  const zipPath = path.join(backupDir, `wp-core-${timestamp}.zip`);
  
  fs.mkdirSync(backupDir, { recursive: true });
  
  const stagingDir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'backup-staging-'));
  
  const preserveFiles = ['wp-config.php', '.htaccess', 'robots.txt'];
  let filesBackedUp = 0;
  
  const entries = fs.readdirSync(targetPath);
  for (const entry of entries) {
    const srcPath = path.join(targetPath, entry);
    
    if (entry === 'wp-content') {
      const destPath = path.join(stagingDir, entry);
      copyRecursiveSync(srcPath, destPath);
      filesBackedUp += countFilesRecursive(srcPath);
    } else if (preserveFiles.includes(entry)) {
      fs.copyFileSync(srcPath, path.join(stagingDir, entry));
      filesBackedUp++;
    } else {
      const stat = fs.statSync(srcPath);
      if (stat.isFile()) {
        fs.copyFileSync(srcPath, path.join(stagingDir, entry));
        filesBackedUp++;
      }
    }
  }
  
  const zip = new AdmZip();
  zip.addLocalFolder(stagingDir);
  zip.writeZip(zipPath);
  
  fs.rmSync(stagingDir, { recursive: true, force: true });
  
  return {
    success: true,
    backupPath: zipPath,
    filesBackedUp,
  };
}

export function copyRecursiveSync(src: string, dest: string): void {
  if (!fs.existsSync(dest)) {
    fs.mkdirSync(dest, { recursive: true });
  }
  
  const entries = fs.readdirSync(src);
  for (const entry of entries) {
    const srcPath = path.join(src, entry);
    const destPath = path.join(dest, entry);
    const stat = fs.statSync(srcPath);
    
    if (stat.isDirectory()) {
      copyRecursiveSync(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

export interface CoreRepairResult {
  success: boolean;
  filesReplaced: string[];
  filesPreserved: string[];
  backupPath: string | null;
  dryRun: boolean;
}

export interface PluginBackupResult {
  success: boolean;
  backupPath: string;
  pluginSlug: string;
  filesBackedUp: number;
}

export function createPluginBackup(pluginsPath: string, pluginSlug: string): PluginBackupResult | null {
  const pluginDir = path.join(pluginsPath, pluginSlug);
  if (!fs.existsSync(pluginDir)) {
    return null;
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const wpRoot = path.dirname(path.dirname(pluginsPath));
  const backupDir = path.join(wpRoot, 'clean-sweep-cli', 'backups');
  const zipPath = path.join(backupDir, `plugin-${pluginSlug}-${timestamp}.zip`);
  
  fs.mkdirSync(backupDir, { recursive: true });
  
  const stagingDir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'plugin-backup-staging-'));
  const pluginStagingDir = path.join(stagingDir, pluginSlug);
  copyRecursiveSync(pluginDir, pluginStagingDir);
  
  const filesBackedUp = countFilesRecursive(pluginStagingDir);
  
  const zip = new AdmZip();
  zip.addLocalFolder(stagingDir);
  zip.writeZip(zipPath);
  
  fs.rmSync(stagingDir, { recursive: true, force: true });
  
  return {
    success: true,
    backupPath: zipPath,
    pluginSlug,
    filesBackedUp,
  };
}

export interface ThemeBackupResult {
  success: boolean;
  backupPath: string;
  themeSlug: string;
  filesBackedUp: number;
}

export function createThemeBackup(themesPath: string, themeSlug: string): ThemeBackupResult | null {
  const themeDir = path.join(themesPath, themeSlug);
  if (!fs.existsSync(themeDir)) {
    return null;
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const wpRoot = path.dirname(path.dirname(themesPath));
  const backupDir = path.join(wpRoot, 'clean-sweep-cli', 'backups');
  const zipPath = path.join(backupDir, `theme-${themeSlug}-${timestamp}.zip`);
  
  fs.mkdirSync(backupDir, { recursive: true });
  
  const stagingDir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'theme-backup-staging-'));
  const themeStagingDir = path.join(stagingDir, themeSlug);
  copyRecursiveSync(themeDir, themeStagingDir);
  
  const filesBackedUp = countFilesRecursive(themeStagingDir);
  
  const zip = new AdmZip();
  zip.addLocalFolder(stagingDir);
  zip.writeZip(zipPath);
  
  fs.rmSync(stagingDir, { recursive: true, force: true });
  
  return {
    success: true,
    backupPath: zipPath,
    themeSlug,
    filesBackedUp,
  };
}