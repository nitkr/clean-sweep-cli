import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import { detectWordPressRoot, formatWpPathError } from '../../wp-path-detector';
import {
  CliOptions,
  WordPressUser,
  UserIssue,
  UsersCheckResult
} from './types';
import {
  parsePhpUsersExport,
  parseSqlExport
} from './parsers';
import {
  runAllUserChecks,
  checkOrphanedSessions,
  checkExpiredSessions
} from './detectors';
import {
  queryDatabase,
  queryAllSessionTokens
} from './db';

// Helper function for output formatting
function formatOutput(data: unknown, useJson: boolean): void {
  // Always use JSON for output since errors need structured data
  console.log(JSON.stringify(data, null, 2));
}

// Check users from file-based sources (wp-users.php, SQL exports)
export function checkUsers(targetPath: string): UsersCheckResult {
  let users: WordPressUser[] = [];
  let source: UsersCheckResult['source'] = 'none';

  const wpUsersPhpPath = path.join(targetPath, 'wp-users.php');
  const sqlExportPath = path.join(targetPath, 'wp-users.sql');

  if (fs.existsSync(wpUsersPhpPath)) {
    try {
      const content = fs.readFileSync(wpUsersPhpPath, 'utf-8');
      users = parsePhpUsersExport(content);
      if (users.length > 0) {
        source = 'wp-users.php';
      }
    } catch {
      // unreadable
    }
  }

  if (source === 'none') {
    const sqlFiles = fs.readdirSync(targetPath).filter(
      (f) => f.endsWith('.sql') && f.toLowerCase().includes('user')
    );

    if (sqlFiles.length > 0) {
      for (const sqlFile of sqlFiles) {
        try {
          const content = fs.readFileSync(path.join(targetPath, sqlFile), 'utf-8');
          const parsed = parseSqlExport(content);
          if (parsed.length > 0) {
            users = parsed;
            source = 'sql-export';
            break;
          }
        } catch {
          // unreadable
        }
      }
    }

    if (source === 'none' && fs.existsSync(sqlExportPath)) {
      try {
        const content = fs.readFileSync(sqlExportPath, 'utf-8');
        users = parseSqlExport(content);
        if (users.length > 0) {
          source = 'sql-export';
        }
      } catch {
        // unreadable
      }
    }
  }

  return buildCheckResult(targetPath, users, source);
}

// Check users from live database
export async function checkUsersFromDatabase(targetPath: string): Promise<UsersCheckResult> {
  const users = await queryDatabase(targetPath);
  const sessionsByUser = await queryAllSessionTokens(targetPath);
  const allUserIds = users.map(u => u.id);
  
  const sessionIssues = [
    ...checkOrphanedSessions(users, sessionsByUser),
    ...checkExpiredSessions(users, sessionsByUser)
  ];
  
  return buildCheckResult(targetPath, users, 'database', sessionIssues);
}

// Build the complete check result from users array
function buildCheckResult(targetPath: string, users: WordPressUser[], source: UsersCheckResult['source'], sessionIssues: UserIssue[] = []): UsersCheckResult {
  const issues = [...runAllUserChecks(users), ...sessionIssues];

  const bySeverity: Record<string, number> = {};
  for (const issue of issues) {
    bySeverity[issue.severity] = (bySeverity[issue.severity] || 0) + 1;
  }

  // Build summary
  const summary = {
    total: users.length,
    administrators: users.filter((u) => u.roles.includes('administrator')).length,
    editors: users.filter((u) => u.roles.includes('editor')).length,
    authors: users.filter((u) => u.roles.includes('author')).length,
    contributors: users.filter((u) => u.roles.includes('contributor')).length,
    subscribers: users.filter((u) => u.roles.includes('subscriber')).length,
    inactiveOver90Days: issues.filter((i) => i.type === 'inactive_user').length,
    disposableEmails: issues.filter((i) => i.type === 'disposable_email').length,
    suspiciousLogins: issues.filter((i) => i.type === 'suspicious_login').length,
  };

  return {
    path: targetPath,
    usersFound: users.length > 0,
    source,
    users,
    issues,
    hasIssues: issues.length > 0,
    bySeverity,
    summary,
  };
}

// Register the users:check command
export function registerUsersCheckCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  program
    .command('users:check')
    .description('Check WordPress users for security issues including shadow accounts, inactive users, and suspicious emails')
    .option('--path <path>', 'Target WordPress directory')
    .option('--json', 'Output results as JSON', false)
    .option('--db', 'Query live database for user data', false)
    .option('--days <days>', 'Days threshold for inactive user detection', '90')
    .action(async (cmdOptions) => {
      const opts = getOpts();
      let targetPath = path.resolve(cmdOptions.path || opts.path);
      const useJson = cmdOptions.json || opts.json;
      const useDatabase = cmdOptions.db || false;

      if (!fs.existsSync(targetPath)) {
        const error = { error: 'Path does not exist', path: targetPath };
        formatOutput(error, useJson);
        process.exit(1);
        return;
      }

      const wpResult = detectWordPressRoot(targetPath);
      if (!wpResult.found) {
        const error = { success: false, error: formatWpPathError(wpResult, 'users:check'), path: targetPath };
        formatOutput(error, useJson);
        process.exit(1);
        return;
      }
      targetPath = wpResult.path;

      if (useJson) {
        let result: UsersCheckResult;
        if (useDatabase) {
          result = await checkUsersFromDatabase(targetPath);
        } else {
          result = checkUsers(targetPath);
        }
        console.log(JSON.stringify(result, null, 2));
        process.exit((result.bySeverity['HIGH'] || 0) > 0 ? 1 : 0);
        return;
      }

      console.log(`Checking WordPress admin users in: ${targetPath}`);

      let result: UsersCheckResult;

      if (useDatabase) {
        result = await checkUsersFromDatabase(targetPath);
      } else {
        result = checkUsers(targetPath);
      }

      if (!result.usersFound) {
        console.warn('Warning: No WordPress user data found. Try --db to query the live database.');
      }

      if (result.usersFound) {
        console.log(`\nSource: ${result.source}`);
        console.log(`\n--- WordPress Users ---`);
        console.log(`Users found: ${result.summary.total}`);
        console.log(`  Administrators: ${result.summary.administrators}`);
        console.log(`  Editors: ${result.summary.editors}`);
        console.log(`  Authors: ${result.summary.authors}`);
        console.log(`  Contributors: ${result.summary.contributors}`);
        console.log(`  Subscribers: ${result.summary.subscribers}`);

        if (result.issues.length === 0) {
          console.log('\n✓ No user security issues found.');
        } else {
          console.log(`\n--- Security Issues (${result.issues.length}) ---`);

          for (const issue of result.issues) {
            console.log(`\n[${issue.severity}] ${issue.description}`);
            console.log(`  → ${issue.recommendation}`);
          }

          console.log('\nSeverity breakdown:');
          for (const sev of ['HIGH', 'MEDIUM', 'LOW']) {
            const count = result.bySeverity[sev] || 0;
            if (count > 0) {
              console.log(`  ${sev}: ${count}`);
            }
          }

          if (result.summary.inactiveOver90Days > 0) {
            console.log(`\n⚠ ${result.summary.inactiveOver90Days} user(s) inactive for 90+ days`);
          }
          if (result.summary.disposableEmails > 0) {
            console.log(`⚠ ${result.summary.disposableEmails} user(s) using disposable emails`);
          }
          if (result.summary.suspiciousLogins > 0) {
            console.log(`⚠ ${result.summary.suspiciousLogins} user(s) with suspicious login names`);
          }
        }
      } else {
        console.log('No user data found. Try --db to query the live database.');
      }

      const hasHighSeverity = (result.bySeverity['HIGH'] || 0) > 0;
      process.exit(hasHighSeverity ? 1 : 0);
      return;
    });
}

// Re-export for backward compatibility
export {
  WordPressUser,
  UserIssue,
  UsersCheckResult,
  CliOptions
} from './types';
