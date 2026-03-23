import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';

export interface WordPressUser {
  id: number;
  login: string;
  email: string;
  displayName: string;
  roles: string[];
  registeredDate?: string;
}

export interface UserIssue {
  user: WordPressUser;
  type: 'default_admin' | 'admin_default_email' | 'multiple_admins' | 'suspicious_login' | 'weak_role_assignment';
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  recommendation: string;
}

export interface UsersCheckResult {
  path: string;
  usersFound: boolean;
  source: 'wp-users.php' | 'sql-export' | 'none';
  users: WordPressUser[];
  issues: UserIssue[];
  hasIssues: boolean;
  bySeverity: Record<string, number>;
}

const DEFAULT_ADMIN_LOGIN = 'admin';
const DEFAULT_ADMIN_EMAIL = 'admin@example.com';

const SUSPICIOUS_LOGIN_PATTERNS = [
  /^admin\d*$/i,
  /^administrator$/i,
  /^root$/i,
  /^test\d*$/i,
  /^user\d*$/i,
  /^demo$/i,
  /^dev$/i,
  /^backup$/i,
  /^temp$/i,
  /^webmaster$/i,
  /^support$/i,
];

const WP_ROLES = ['administrator', 'editor', 'author', 'contributor', 'subscriber'];
const ADMIN_ROLES = ['administrator'];

export function parsePhpUsersExport(content: string): WordPressUser[] {
  const users: WordPressUser[] = [];

  const stdAssignRegex = /^\$(\w+)\s*=\s*new\s+stdClass\s*\(\s*\)\s*;/m;
  const propAssignRegex = /^\$(\w+)->(\w+)\s*=\s*'([^']*)'/gm;

  if (stdAssignRegex.test(content)) {
    const userBlocks: Record<string, Record<string, string>> = {};

    let propMatch;
    while ((propMatch = propAssignRegex.exec(content)) !== null) {
      const varName = propMatch[1];
      const key = propMatch[2];
      const value = propMatch[3];

      if (!userBlocks[varName]) {
        userBlocks[varName] = {};
      }
      userBlocks[varName][key] = value;
    }

    for (const props of Object.values(userBlocks)) {
      if (props.ID && props.user_login) {
        users.push({
          id: parseInt(props.ID, 10),
          login: props.user_login,
          email: props.user_email || '',
          displayName: props.display_name || props.user_login,
          roles: props.roles ? props.roles.split(',').map((r) => r.trim().toLowerCase()) : [],
        });
      }
    }

    if (users.length > 0) {
      return users;
    }
  }

  return parsePhpInsertStatements(content);
}

function parsePhpInsertStatements(content: string): WordPressUser[] {
  const users: WordPressUser[] = [];

  const insertRegex = /INSERT\s+INTO\s+[`'"]?wp_users[`'"]?\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)/gi;

  let match;
  while ((match = insertRegex.exec(content)) !== null) {
    const columns = match[1].split(',').map((c) => c.trim().replace(/[`'"]/g, '').toLowerCase());
    const rawValues = match[2];
    const values = rawValues.split(',').map((v) => v.trim().replace(/^['"]|['"]$/g, ''));

    const getValue = (col: string): string => {
      const idx = columns.indexOf(col);
      return idx >= 0 && idx < values.length ? values[idx] : '';
    };

    const id = parseInt(getValue('id') || getValue('ID'), 10);
    const login = getValue('user_login');
    const email = getValue('user_email');

    if (id && login) {
      users.push({
        id,
        login,
        email,
        displayName: getValue('display_name') || login,
        roles: [],
      });
    }
  }

  return users;
}

export function parseSqlExport(content: string): WordPressUser[] {
  const users: WordPressUser[] = [];
  const userRoles: Record<number, string[]> = {};

  const roleInsertRegex = /INSERT\s+INTO\s+[`'"]?wp_usermeta[`'"]?\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)/gi;

  let match;
  while ((match = roleInsertRegex.exec(content)) !== null) {
    const columns = match[1].split(',').map((c) => c.trim().replace(/[`'"]/g, '').toLowerCase());
    const rawValues = match[2];
    const values = rawValues.split(',').map((v) => v.trim().replace(/^['"]|['"]$/g, ''));

    const getValue = (col: string): string => {
      const idx = columns.indexOf(col);
      return idx >= 0 && idx < values.length ? values[idx] : '';
    };

    const metaKey = getValue('meta_key');
    if (metaKey === 'wp_capabilities') {
      const userId = parseInt(getValue('user_id'), 10);
      const metaValue = getValue('meta_value');
      if (userId && metaValue) {
        const roleMatches = metaValue.match(/s:\d+:"(\w+)"/g);
        if (roleMatches) {
          userRoles[userId] = roleMatches
            .map((r) => r.match(/"(\w+)"/)?.[1] || '')
            .filter(Boolean);
        }
      }
    }
  }

  const userInsertRegex = /INSERT\s+INTO\s+[`'"]?wp_users[`'"]?\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)/gi;

  while ((match = userInsertRegex.exec(content)) !== null) {
    const columns = match[1].split(',').map((c) => c.trim().replace(/[`'"]/g, '').toLowerCase());
    const rawValues = match[2];
    const values = rawValues.split(',').map((v) => v.trim().replace(/^['"]|['"]$/g, ''));

    const getValue = (col: string): string => {
      const idx = columns.indexOf(col);
      return idx >= 0 && idx < values.length ? values[idx] : '';
    };

    const id = parseInt(getValue('id') || getValue('ID'), 10);
    const login = getValue('user_login');
    const email = getValue('user_email');

    if (id && login) {
      users.push({
        id,
        login,
        email,
        displayName: getValue('display_name') || login,
        roles: userRoles[id] || [],
      });
    }
  }

  return users;
}

export function detectSuspiciousLogins(users: WordPressUser[]): UserIssue[] {
  const issues: UserIssue[] = [];

  for (const user of users) {
    for (const pattern of SUSPICIOUS_LOGIN_PATTERNS) {
      if (pattern.test(user.login) && user.login.toLowerCase() !== 'admin') {
        issues.push({
          user,
          type: 'suspicious_login',
          severity: 'MEDIUM',
          description: `User "${user.login}" has a suspicious login name`,
          recommendation: `Rename or remove the account "${user.login}" to reduce attack surface`,
        });
        break;
      }
    }
  }

  return issues;
}

export function checkDefaultAdmin(users: WordPressUser[]): UserIssue | null {
  const defaultAdmin = users.find(
    (u) => u.login.toLowerCase() === DEFAULT_ADMIN_LOGIN
  );

  if (defaultAdmin) {
    return {
      user: defaultAdmin,
      type: 'default_admin',
      severity: 'HIGH',
      description: `Default "admin" username found (ID: ${defaultAdmin.id})`,
      recommendation: 'Rename the default admin account to a non-obvious username',
    };
  }

  return null;
}

export function checkDefaultEmail(users: WordPressUser[]): UserIssue[] {
  return users
    .filter((u) => u.email.toLowerCase() === DEFAULT_ADMIN_EMAIL)
    .map((u) => ({
      user: u,
      type: 'admin_default_email' as const,
      severity: 'HIGH' as const,
      description: `User "${u.login}" uses default admin@example.com email`,
      recommendation: `Update email for "${u.login}" to a real, monitored email address`,
    }));
}

export function checkMultipleAdmins(users: WordPressUser[]): UserIssue[] {
  const admins = users.filter(
    (u) => u.roles.some((r) => ADMIN_ROLES.includes(r))
  );

  if (admins.length > 1) {
    return admins.map((u) => ({
      user: u,
      type: 'multiple_admins' as const,
      severity: 'LOW' as const,
      description: `${admins.length} administrator accounts found`,
      recommendation: 'Review admin accounts and reduce to minimum necessary',
    }));
  }

  return [];
}

export function checkWeakRoleAssignment(users: WordPressUser[]): UserIssue[] {
  const issues: UserIssue[] = [];

  for (const user of users) {
    const validRoles = user.roles.filter((r) => WP_ROLES.includes(r));
    if (user.roles.length > 0 && validRoles.length === 0) {
      issues.push({
        user,
        type: 'weak_role_assignment',
        severity: 'MEDIUM',
        description: `User "${user.login}" has unrecognized role(s): ${user.roles.join(', ')}`,
        recommendation: `Review roles for user "${user.login}" and assign a valid WordPress role`,
      });
    }
  }

  return issues;
}

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

  const issues: UserIssue[] = [];

  if (users.length > 0) {
    const defaultAdminIssue = checkDefaultAdmin(users);
    if (defaultAdminIssue) {
      issues.push(defaultAdminIssue);
    }

    issues.push(...checkDefaultEmail(users));
    issues.push(...checkMultipleAdmins(users));
    issues.push(...detectSuspiciousLogins(users));
    issues.push(...checkWeakRoleAssignment(users));
  }

  const bySeverity: Record<string, number> = {};
  for (const issue of issues) {
    bySeverity[issue.severity] = (bySeverity[issue.severity] || 0) + 1;
  }

  return {
    path: targetPath,
    usersFound: users.length > 0,
    source,
    users,
    issues,
    hasIssues: issues.length > 0,
    bySeverity,
  };
}

export function registerUsersCheckCommand(
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
    .command('users:check')
    .description('Check WordPress admin users for suspicious accounts and default settings')
    .option('--path <path>', 'Target WordPress directory')
    .option('--json', 'Output results as JSON', false)
    .action((cmdOptions) => {
      const opts = getOpts();
      const targetPath = path.resolve(cmdOptions.path || opts.path);
      const useJson = cmdOptions.json || opts.json;

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
        console.log(`Checking WordPress admin users in: ${targetPath}`);
      }

      const result = checkUsers(targetPath);

      if (!result.usersFound && !useJson) {
        console.warn('Warning: No WordPress user data found (wp-users.php or SQL export)');
      }

      if (useJson) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        if (result.usersFound) {
          console.log(`\nSource: ${result.source}`);
          console.log(`Users found: ${result.users.length}`);

          // Users list
          console.log('\n--- WordPress Users ---');
          for (const user of result.users) {
            const roleStr = user.roles.length > 0 ? user.roles.join(', ') : 'unknown';
            console.log(`  [${user.id}] ${user.login} (${user.email}) - ${roleStr}`);
          }

          // Issues
          if (result.issues.length === 0) {
            console.log('\nNo user security issues found.');
          } else {
            console.log(`\n--- Security Issues (${result.issues.length}) ---`);

            for (const issue of result.issues) {
              console.log(`  [${issue.severity}] ${issue.description}`);
              console.log(`    Recommendation: ${issue.recommendation}`);
            }

            console.log('\nSeverity breakdown:');
            for (const sev of ['HIGH', 'MEDIUM', 'LOW']) {
              const count = result.bySeverity[sev] || 0;
              if (count > 0) {
                console.log(`  ${sev}: ${count}`);
              }
            }
          }
        } else {
          console.log('No user data files found. Place wp-users.php or a SQL export in the target directory.');
        }
      }

      const hasHighSeverity = (result.bySeverity['HIGH'] || 0) > 0;
      process.exit(hasHighSeverity ? 1 : 0);
    });
}
