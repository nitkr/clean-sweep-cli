import * as fs from 'fs';
import * as path from 'path';

export interface BackupResult {
  success: boolean;
  backupPath: string;
  filesBackedUp: number;
}

export function createBackup(targetPath: string): BackupResult {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupDir = path.join(path.dirname(targetPath), 'backups', `wp-core-${timestamp}`);
  
  fs.mkdirSync(backupDir, { recursive: true });
  
  const preserveFiles = ['wp-config.php', '.htaccess', 'robots.txt'];
  let filesBackedUp = 0;
  
  const entries = fs.readdirSync(targetPath);
  for (const entry of entries) {
    const srcPath = path.join(targetPath, entry);
    
    if (entry === 'wp-content' || preserveFiles.includes(entry)) {
      const destPath = path.join(backupDir, entry);
      copyRecursiveSync(srcPath, destPath);
      filesBackedUp++;
    } else {
      const stat = fs.statSync(srcPath);
      if (stat.isFile()) {
        fs.copyFileSync(srcPath, path.join(backupDir, entry));
        filesBackedUp++;
      }
    }
  }
  
  return {
    success: true,
    backupPath: backupDir,
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
  const backupDir = path.join(path.dirname(pluginsPath), 'backups', `plugin-${pluginSlug}-${timestamp}`);
  
  fs.mkdirSync(backupDir, { recursive: true });
  copyRecursiveSync(pluginDir, path.join(backupDir, pluginSlug));
  
  return {
    success: true,
    backupPath: backupDir,
    pluginSlug,
    filesBackedUp: 1,
  };
}
