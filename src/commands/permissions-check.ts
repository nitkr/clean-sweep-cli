import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import fg from 'fast-glob';

export interface PermissionIssue {
  file: string;
  type: 'world_writable' | 'world_readable_sensitive' | 'unexpected_executable' | 'setuid_setgid' | 'directory_world_writable';
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  currentMode: string;
  suggestedMode: string;
  description: string;
}

export interface PermissionsCheckResult {
  path: string;
  totalFiles: number;
  totalChecked: number;
  issues: PermissionIssue[];
  hasIssues: boolean;
  bySeverity: Record<string, number>;
}

const IGNORE_PATTERNS = ['**/node_modules/**', '**/.git/**', '**/dist/**'];

const SENSITIVE_EXTENSIONS = ['.env', '.pem', '.key', '.secret', '.credentials'];

const EXECUTABLE_EXTENSIONS = new Set([
  '.sh', '.bash', '.zsh', '.bat', '.cmd', '.ps1', '.com', '.exe', '.bin',
]);

const NON_EXECUTABLE_EXTENSIONS = new Set([
  '.ts', '.js', '.mjs', '.cjs', '.json', '.md', '.txt', '.yml', '.yaml',
  '.xml', '.html', '.css', '.scss', '.less', '.svg', '.png', '.jpg',
  '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.eot',
  '.map', '.d.ts', '.lock', '.log', '.csv', '.tsv',
]);

function modeToString(mode: number): string {
  return '0' + (mode & 0o777).toString(8);
}

function isWorldWritable(mode: number): boolean {
  return (mode & 0o002) !== 0;
}

function isDirectoryWorldWritable(mode: number): boolean {
  return (mode & 0o002) !== 0;
}

function isSetuidOrSetgid(mode: number): boolean {
  return (mode & 0o4000) !== 0 || (mode & 0o2000) !== 0;
}

function isExecutable(mode: number): boolean {
  return (mode & 0o111) !== 0;
}

function suggestModeForIssue(issueType: PermissionIssue['type'], currentMode: number): string {
  const mode = currentMode & 0o777;
  switch (issueType) {
    case 'world_writable':
    case 'directory_world_writable':
      return modeToString(mode & ~0o002);
    case 'unexpected_executable':
      return modeToString(mode & ~0o111);
    case 'setuid_setgid':
      return modeToString(mode & ~0o6000);
    case 'world_readable_sensitive':
      return modeToString(mode & ~0o004);
    default:
      return modeToString(mode);
  }
}

function classifyExecutable(filePath: string, mode: number): PermissionIssue | null {
  const ext = path.extname(filePath).toLowerCase();

  if (EXECUTABLE_EXTENSIONS.has(ext)) {
    return null;
  }

  if (NON_EXECUTABLE_EXTENSIONS.has(ext)) {
    return {
      file: filePath,
      type: 'unexpected_executable',
      severity: 'MEDIUM',
      currentMode: modeToString(mode),
      suggestedMode: suggestModeForIssue('unexpected_executable', mode),
      description: `Source/config file ${path.basename(filePath)} has executable permission`,
    };
  }

  return null;
}

export function checkPermissions(targetPath: string): PermissionsCheckResult {
  const files = fg.sync(['**/*', '**/.*'], {
    cwd: targetPath,
    absolute: true,
    onlyFiles: true,
    ignore: IGNORE_PATTERNS,
    dot: true,
  });

  const issues: PermissionIssue[] = [];

  for (const file of files) {
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(file);
    } catch {
      continue;
    }

    if (stat.isSymbolicLink()) {
      continue;
    }

    const mode = stat.mode;

    if (isSetuidOrSetgid(mode)) {
      issues.push({
        file,
        type: 'setuid_setgid',
        severity: 'HIGH',
        currentMode: modeToString(mode),
        suggestedMode: suggestModeForIssue('setuid_setgid', mode),
        description: `File ${path.basename(file)} has setuid/setgid bit set`,
      });
    }

    if (isWorldWritable(mode)) {
      issues.push({
        file,
        type: 'world_writable',
        severity: 'HIGH',
        currentMode: modeToString(mode),
        suggestedMode: suggestModeForIssue('world_writable', mode),
        description: `File ${path.basename(file)} is world-writable`,
      });
    }

    const ext = path.extname(file).toLowerCase();
    const basename = path.basename(file).toLowerCase();
    const isSensitive = SENSITIVE_EXTENSIONS.includes(ext) || SENSITIVE_EXTENSIONS.includes(basename);
    if (isSensitive) {
      const readableByOthers = (mode & 0o004) !== 0;
      if (readableByOthers) {
        issues.push({
          file,
          type: 'world_readable_sensitive',
          severity: 'HIGH',
          currentMode: modeToString(mode),
          suggestedMode: suggestModeForIssue('world_readable_sensitive', mode),
          description: `Sensitive file ${path.basename(file)} is world-readable`,
        });
      }
    }

    if (isExecutable(mode)) {
      const execIssue = classifyExecutable(file, mode);
      if (execIssue) {
        issues.push(execIssue);
      }
    }
  }

  const dirEntries = fg.sync(['**/*', '**/.*'], {
    cwd: targetPath,
    absolute: true,
    onlyDirectories: true,
    ignore: IGNORE_PATTERNS,
    dot: true,
  });

  for (const dir of dirEntries) {
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(dir);
    } catch {
      continue;
    }

    if (isDirectoryWorldWritable(stat.mode)) {
      issues.push({
        file: dir,
        type: 'directory_world_writable',
        severity: 'MEDIUM',
        currentMode: modeToString(stat.mode),
        suggestedMode: suggestModeForIssue('directory_world_writable', stat.mode),
        description: `Directory ${path.basename(dir)} is world-writable`,
      });
    }
  }

  const bySeverity: Record<string, number> = {};
  for (const issue of issues) {
    bySeverity[issue.severity] = (bySeverity[issue.severity] || 0) + 1;
  }

  return {
    path: targetPath,
    totalFiles: files.length,
    totalChecked: files.length,
    issues,
    hasIssues: issues.length > 0,
    bySeverity,
  };
}

export function registerPermissionsCheckCommand(
  program: Command,
  getOpts: () => {
    dryRun: boolean;
    force: boolean;
    json: boolean;
    path: string;
    verbose: boolean;
    logLevel: string;
  }
): void {
  program
    .command('permissions:check')
    .description('Audit file permissions for common security issues')
    .option('--path <path>', 'Target directory to check')
    .option('--json', 'Output results as JSON', false)
    .option('--fix', 'Show suggested permission fixes', false)
    .action((cmdOptions) => {
      const opts = getOpts();
      const targetPath = path.resolve(cmdOptions.path || opts.path);
      const useJson = cmdOptions.json || opts.json;
      const showFix = cmdOptions.fix;

      if (!fs.existsSync(targetPath)) {
        const error = { error: 'Path does not exist', path: targetPath };
        if (useJson) {
          console.log(JSON.stringify(error, null, 2));
        } else {
          console.error(`Error: Path does not exist: ${targetPath}`);
        }
        process.exit(1);
      }

      if (!fs.statSync(targetPath).isDirectory()) {
        const error = { error: 'Path is not a directory', path: targetPath };
        if (useJson) {
          console.log(JSON.stringify(error, null, 2));
        } else {
          console.error(`Error: Path is not a directory: ${targetPath}`);
        }
        process.exit(1);
      }

      if (!useJson) {
        console.log(`Checking permissions in: ${targetPath}`);
      }

      const result = checkPermissions(targetPath);

      if (useJson) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.log(`\nFiles scanned: ${result.totalChecked}`);

        if (result.issues.length === 0) {
          console.log('\nNo permission issues found.');
        } else {
          console.log(`\nFound ${result.issues.length} permission issue(s):`);

          for (const issue of result.issues) {
            console.log(`  [${issue.severity}] ${issue.description}`);
            console.log(`    File: ${issue.file}`);
            console.log(`    Mode: ${issue.currentMode}`);
            if (showFix) {
              console.log(`    Fix: chmod ${issue.suggestedMode} "${issue.file}"`);
            }
          }

          console.log('\nSeverity breakdown:');
          for (const sev of ['HIGH', 'MEDIUM', 'LOW']) {
            const count = result.bySeverity[sev] || 0;
            if (count > 0) {
              console.log(`  ${sev}: ${count}`);
            }
          }

          if (showFix) {
            console.log('\nSuggested fixes:');
            for (const issue of result.issues) {
              console.log(`  chmod ${issue.suggestedMode} "${issue.file}"`);
            }
          }
        }
      }

      process.exit(result.hasIssues ? 1 : 0);
    });
}
