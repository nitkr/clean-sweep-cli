import * as path from 'path';
import * as fs from 'fs';

export interface WpPathResult {
  path: string;
  found: boolean;
  searchedPaths: string[];
}

export function findWordPressRoot(startPath: string): string | null {
  const searchedPaths: string[] = [];
  let current = path.resolve(startPath);

  while (true) {
    searchedPaths.push(current);

    if (fs.existsSync(path.join(current, 'wp-config.php'))) {
      return current;
    }

    const parent = path.dirname(current);
    if (parent === current) {
      return null;
    }
    current = parent;
  }
}

export function detectWordPressRoot(startPath?: string): WpPathResult {
  const resolved = path.resolve(startPath || process.cwd());
  const searchedPaths: string[] = [];
  let current = resolved;

  while (true) {
    searchedPaths.push(current);

    if (fs.existsSync(path.join(current, 'wp-config.php'))) {
      return { path: current, found: true, searchedPaths };
    }

    const parent = path.dirname(current);
    if (parent === current) {
      return { path: resolved, found: false, searchedPaths };
    }
    current = parent;
  }
}

export function resolveWordPressPath(targetPath: string): WpPathResult {
  const resolved = path.resolve(targetPath);
  const searchedPaths: string[] = [];

  if (fs.existsSync(path.join(resolved, 'wp-config.php'))) {
    searchedPaths.push(resolved);
    return { path: resolved, found: true, searchedPaths };
  }

  return detectWordPressRoot(resolved);
}

export function formatWpPathError(result: WpPathResult, commandName: string): string {
  return (
    `WordPress installation not found. Searched: ${result.searchedPaths.join(', ')}\n` +
    `Use "clean-sweep ${commandName} --path /path/to/wordpress" to specify the WordPress root.`
  );
}
