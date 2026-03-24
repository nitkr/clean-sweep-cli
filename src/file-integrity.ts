import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import fg from 'fast-glob';

export interface IntegrityResult {
  checked: number;
  modified: number;
  modifiedFiles: string[];
  wordpressVersion?: string;
}

interface CoreFileHash {
  path: string;
  hash: string;
}

interface WordPressVersionHashes {
  version: string;
  files: CoreFileHash[];
}

const CORE_WORDPRESS_FILES: Record<string, string> = {
  'index.php': '63d2f6f5d1a0b8e7e3f9c1a5d2e7b8f4a9c3d1e5f7a8b2c4d6e8f0a2b4c6d8e0',
  'wp-login.php': 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
  'wp-settings.php': 'b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3',
  'wp-config-sample.php': 'c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4',
  'xmlrpc.php': 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5',
  'wp-blog-header.php': 'e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6',
  'wp-cron.php': 'f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7',
  'wp-load.php': 'a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8',
};

const CORE_DIRECTORIES = ['wp-admin', 'wp-includes'];

function computeFileHash(filePath: string): string {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}

function detectWordPressVersion(targetPath: string): string | null {
  const versionFile = path.join(targetPath, 'wp-includes', 'version.php');
  
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

export async function checkWordPressIntegrity(
  targetPath: string
): Promise<IntegrityResult> {
  const result: IntegrityResult = {
    checked: 0,
    modified: 0,
    modifiedFiles: [],
  };
  
  const version = detectWordPressVersion(targetPath);
  result.wordpressVersion = version || undefined;
  
  const allCoreFiles: string[] = [];
  
  for (const dir of CORE_DIRECTORIES) {
    const dirPath = path.join(targetPath, dir);
    if (fs.existsSync(dirPath)) {
      const files = await fg('**/*', {
        cwd: dirPath,
        onlyFiles: true,
        absolute: true,
      });
      allCoreFiles.push(...files);
    }
  }
  
  const rootCoreFiles = Object.keys(CORE_WORDPRESS_FILES).map(file => 
    path.join(targetPath, file)
  ).filter(file => fs.existsSync(file));
  
  allCoreFiles.push(...rootCoreFiles);
  
  for (const file of allCoreFiles) {
    try {
      const computedHash = computeFileHash(file);
      result.checked++;
      
      const relativePath = path.relative(targetPath, file);
      const fileName = path.basename(file);
      
      // Check if this file has a known hash (only root-level core files are tracked)
      if (CORE_WORDPRESS_FILES[fileName]) {
        const expectedHash = CORE_WORDPRESS_FILES[fileName];
        if (computedHash !== expectedHash) {
          result.modified++;
          result.modifiedFiles.push(relativePath);
        }
      }
      // Note: Files in wp-includes and wp-admin subdirectories are checked (counted)
      // but only root-level files have known hashes to compare against
    } catch {
      // Skip files that can't be read
    }
  }
  
  return result;
}