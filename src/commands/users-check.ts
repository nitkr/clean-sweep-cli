import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import { exec } from 'child_process';
import { detectWordPressRoot, formatWpPathError } from '../wp-path-detector';

interface CliOptions {
  dryRun: boolean;
  force: boolean;
  json: boolean;
  path: string;
  verbose: boolean;
}

export interface WordPressUser {
  id: number;
  login: string;
  email: string;
  displayName: string;
  roles: string[];
  registeredDate?: string;
  lastLoginDate?: string;
  userStatus?: string;
}

export interface UserIssue {
  user: WordPressUser;
  type: 'default_admin' | 'admin_default_email' | 'multiple_admins' | 'suspicious_login' | 'weak_role_assignment' | 'inactive_user' | 'disposable_email' | 'spam_email' | 'no_role' | 'deleted_status';
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  recommendation: string;
}

export interface UsersCheckResult {
  path: string;
  usersFound: boolean;
  source: 'database' | 'wp-users.php' | 'sql-export' | 'none';
  users: WordPressUser[];
  issues: UserIssue[];
  hasIssues: boolean;
  bySeverity: Record<string, number>;
  summary: {
    total: number;
    administrators: number;
    editors: number;
    authors: number;
    contributors: number;
    subscribers: number;
    inactiveOver90Days: number;
    disposableEmails: number;
    suspiciousLogins: number;
  };
}

const DEFAULT_ADMIN_LOGIN = 'admin';
const DEFAULT_ADMIN_EMAIL = 'admin@example.com';

// Disposable email domains that should be flagged
const DISPOSABLE_EMAIL_DOMAINS = [
  'mailinator.com', 'tempmail.com', '10minutemail.com', 'guerrillamail.com',
  'throwaway.email', 'temp-mail.org', 'fakeinbox.com', 'trashmail.com',
  'maildrop.cc', 'getnada.com', 'mohmal.com', 'tempail.com', 'discard.email',
  'sharklasers.com', 'grr.la', 'guerrillamailblock.com', 'pokemail.net',
  'spam4.me', 'tempinbox.com', 'yopmail.com', 'getairmail.com'
];

// Known spam/malicious email domains
const SPAM_EMAIL_DOMAINS = [
  'spam.com', 'spammer.com', 'junkmail.com', 'tempmailaddress.com'
];

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
  /^sysadmin$/i,
  /^mysql$/i,
  /^postgres$/i,
  /^oracle$/i,
];

const WP_ROLES = ['administrator', 'editor', 'author', 'contributor', 'subscriber'];
const ADMIN_ROLES = ['administrator'];

function formatOutput(data: unknown, useJson: boolean): void {
  // Always use JSON for output since errors need structured data
  // Even in non-JSON mode, errors are better as JSON for debugging
  console.log(JSON.stringify(data, null, 2));
}

function isDisposableEmail(email: string): boolean {
  const domain = email.split('@')[1]?.toLowerCase();
  if (!domain) return false;
  return DISPOSABLE_EMAIL_DOMAINS.some(d => domain === d || domain.endsWith('.' + d));
}

function isSpamEmail(email: string): boolean {
  const domain = email.split('@')[1]?.toLowerCase();
  if (!domain) return false;
  return SPAM_EMAIL_DOMAINS.some(d => domain === d || domain.endsWith('.' + d));
}

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
          description: `User "${user.login}" has a suspicious login name pattern`,
          recommendation: `Review account "${user.login}" - such names are commonly used by attackers`,
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

export function checkNoRole(users: WordPressUser[]): UserIssue[] {
  return users
    .filter((u) => u.roles.length === 0)
    .map((u) => ({
      user: u,
      type: 'no_role' as const,
      severity: 'LOW' as const,
      description: `User "${u.login}" has no assigned roles`,
      recommendation: `Assign appropriate role to "${u.login}" or remove if not needed`,
    }));
}

export function checkDisposableEmails(users: WordPressUser[]): UserIssue[] {
  return users
    .filter((u) => isDisposableEmail(u.email))
    .map((u) => ({
      user: u,
      type: 'disposable_email' as const,
      severity: 'HIGH' as const,
      description: `User "${u.login}" uses disposable email: ${u.email}`,
      recommendation: `Disposable emails are commonly used for spam/attack accounts - investigate "${u.login}"`,
    }));
}

export function checkSpamEmails(users: WordPressUser[]): UserIssue[] {
  return users
    .filter((u) => isSpamEmail(u.email))
    .map((u) => ({
      user: u,
      type: 'spam_email' as const,
      severity: 'HIGH' as const,
      description: `User "${u.login}" uses known spam email: ${u.email}`,
      recommendation: `Remove or flag account "${u.login}" - email domain is associated with spam`,
    }));
}

export function checkInactiveUsers(users: WordPressUser[], daysThreshold: number = 90): UserIssue[] {
  const issues: UserIssue[] = [];
  const now = new Date();
  const thresholdMs = daysThreshold * 24 * 60 * 60 * 1000;

  for (const user of users) {
    if (user.lastLoginDate) {
      const lastLogin = new Date(user.lastLoginDate);
      const inactiveMs = now.getTime() - lastLogin.getTime();
      if (inactiveMs > thresholdMs) {
        const daysInactive = Math.floor(inactiveMs / (24 * 60 * 60 * 1000));
        issues.push({
          user,
          type: 'inactive_user',
          severity: 'MEDIUM',
          description: `User "${user.login}" inactive for ${daysInactive} days (last login: ${user.lastLoginDate})`,
          recommendation: `Review if account "${user.login}" is still needed - zombie accounts are attack targets`,
        });
      }
    }
  }

  return issues;
}

export function checkUserStatus(users: WordPressUser[]): UserIssue[] {
  const issues: UserIssue[] = [];

  for (const user of users) {
    // Check userStatus field if present
    if (user.userStatus) {
      const status = user.userStatus.toLowerCase();
      if (status === 'spam' || status === 'deleted' || status === 'pending') {
        issues.push({
          user,
          type: 'deleted_status',
          severity: 'MEDIUM',
          description: `User "${user.login}" has suspicious status: ${user.userStatus}`,
          recommendation: `Review account "${user.login}" - status "${user.userStatus}" may indicate a disabled or compromised account`,
        });
      }
    }
  }

  return issues;
}

export interface DbCredentials {
  host: string;
  name: string;
  user: string;
  pass: string;
  prefix: string;
}

export function parseWpConfig(wpConfigPath: string): DbCredentials | null {
  if (!fs.existsSync(wpConfigPath)) {
    return null;
  }

  try {
    const content = fs.readFileSync(wpConfigPath, 'utf-8');

    const hostMatch = content.match(/define\s*\(\s*['"]DB_HOST['"]\s*,\s*['"]([^'"]+)['"]\s*\)/);
    const nameMatch = content.match(/define\s*\(\s*['"]DB_NAME['"]\s*,\s*['"]([^'"]+)['"]\s*\)/);
    const userMatch = content.match(/define\s*\(\s*['"]DB_USER['"]\s*,\s*['"]([^'"]+)['"]\s*\)/);
    const passMatch = content.match(/define\s*\(\s*['"]DB_PASSWORD['"]\s*,\s*['"]([^'"]+)['"]\s*\)/);
    const prefixMatch = content.match(/\$table_prefix\s*=\s*['"]([^'"]*)['"]/);

    if (hostMatch && nameMatch && userMatch) {
      return {
        host: hostMatch[1],
        name: nameMatch[1],
        user: userMatch[1],
        pass: passMatch ? passMatch[1] : '',
        prefix: prefixMatch ? prefixMatch[1] : 'wp_',
      };
    }
  } catch {
    return null;
  }

  return null;
}

function execPromise(command: string): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    exec(command, { maxBuffer: 10 * 1024 * 1024 }, (error, stdout) => {
      if (error) {
        reject(error);
      } else {
        resolve(stdout);
      }
    });
  });
}

async function queryDatabase(wpPath: string): Promise<WordPressUser[]> {
  const wpConfigPath = path.join(wpPath, 'wp-config.php');
  const creds = parseWpConfig(wpConfigPath);
  
  if (!creds) {
    return [];
  }

  const users: WordPressUser[] = [];
  const { host, name, user, pass, prefix } = creds;

  try {
    // Query users table
    const userQuery = `SELECT ID, user_login, user_email, display_name, user_registered FROM ${prefix}users ORDER BY ID`;
    const userCmd = `mysql -h "${host}" -u "${user}"${pass ? ` -p"${pass}"` : ''} "${name}" -e "${userQuery}" -B`;
    
    const userOutput = await execPromise(userCmd);
    const userLines = userOutput.trim().split('\n').slice(1); // Skip header
    
    for (const line of userLines) {
      const fields = line.split('\t');
      if (fields.length >= 5) {
        const userId = parseInt(fields[0], 10);
        if (userId) {
          // Query user meta for roles
          const roleQuery = `SELECT meta_value FROM ${prefix}usermeta WHERE user_id = ${userId} AND meta_key = '${prefix}capabilities'`;
          const roleCmd = `mysql -h "${host}" -u "${user}"${pass ? ` -p"${pass}"` : ''} "${name}" -e "${roleQuery}" -B`;
          
          let roles: string[] = [];
          try {
            const roleOutput = await execPromise(roleCmd);
            const roleLines = roleOutput.trim().split('\n').slice(1);
            if (roleLines.length > 0 && roleLines[0]) {
              const roleMatch = roleLines[0].match(/s:\d+:"(\w+)"/g);
              if (roleMatch) {
                roles = roleMatch.map((r: string) => r.match(/"(\w+)"/)?.[1] || '').filter(Boolean);
              }
            }
          } catch {
            // No roles found
          }

          // Query last login (from last_login meta if available)
          let lastLoginDate: string | undefined;
          try {
            const loginQuery = `SELECT meta_value FROM ${prefix}usermeta WHERE user_id = ${userId} AND meta_key = 'last_login'`;
            const loginCmd = `mysql -h "${host}" -u "${user}"${pass ? ` -p"${pass}"` : ''} "${name}" -e "${loginQuery}" -B`;
            const loginOutput = await execPromise(loginCmd);
            const loginLines = loginOutput.trim().split('\n').slice(1);
            if (loginLines.length > 0 && loginLines[0]) {
              const timestamp = parseInt(loginLines[0], 10);
              if (timestamp) {
                lastLoginDate = new Date(timestamp * 1000).toISOString();
              }
            }
          } catch {
            // No last login data
          }

          // Query user status (spam, deleted flags)
          let userStatus: string | undefined;
          try {
            // Check for spam status
            const spamQuery = `SELECT meta_value FROM ${prefix}usermeta WHERE user_id = ${userId} AND meta_key = 'spam'`;
            const spamCmd = `mysql -h "${host}" -u "${user}"${pass ? ` -p"${pass}"` : ''} "${name}" -e "${spamQuery}" -B`;
            const spamOutput = await execPromise(spamCmd);
            const spamLines = spamOutput.trim().split('\n').slice(1);
            if (spamLines.length > 0 && spamLines[0] === '1') {
              userStatus = 'spam';
            }
          } catch {
            // No spam status
          }

          try {
            // Check for deleted status
            if (!userStatus) {
              const deletedQuery = `SELECT meta_value FROM ${prefix}usermeta WHERE user_id = ${userId} AND meta_key = 'deleted'`;
              const deletedCmd = `mysql -h "${host}" -u "${user}"${pass ? ` -p"${pass}"` : ''} "${name}" -e "${deletedQuery}" -B`;
              const deletedOutput = await execPromise(deletedCmd);
              const deletedLines = deletedOutput.trim().split('\n').slice(1);
              if (deletedLines.length > 0 && deletedLines[0] === '1') {
                userStatus = 'deleted';
              }
            }
          } catch {
            // No deleted status
          }

          users.push({
            id: userId,
            login: fields[1],
            email: fields[2],
            displayName: fields[3],
            registeredDate: fields[4],
            lastLoginDate,
            userStatus,
            roles,
          });
        }
      }
    }
  } catch {
    // Database query failed
  }

  return users;
}

export async function checkUsersFromDatabase(targetPath: string): Promise<UsersCheckResult> {
  const users = await queryDatabase(targetPath);
  
  return buildCheckResult(targetPath, users, 'database');
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

  return buildCheckResult(targetPath, users, source);
}

function buildCheckResult(targetPath: string, users: WordPressUser[], source: UsersCheckResult['source']): UsersCheckResult {
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
    issues.push(...checkNoRole(users));
    issues.push(...checkDisposableEmails(users));
    issues.push(...checkSpamEmails(users));
    issues.push(...checkInactiveUsers(users));
    issues.push(...checkUserStatus(users));
  }

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

      if (!useJson) {
        console.log(`Checking WordPress admin users in: ${targetPath}`);
      }

      let result: UsersCheckResult;

      if (useDatabase) {
        result = await checkUsersFromDatabase(targetPath);
      } else {
        result = checkUsers(targetPath);
      }

      if (!result.usersFound && !useJson) {
        console.warn('Warning: No WordPress user data found. Try --db to query the live database.');
      }

      if (useJson) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        if (result.usersFound) {
          console.log(`\nSource: ${result.source}`);
          console.log(`\n--- WordPress Users ---`);
          console.log(`Users found: ${result.summary.total}`);
          console.log(`  Administrators: ${result.summary.administrators}`);
          console.log(`  Editors: ${result.summary.editors}`);
          console.log(`  Authors: ${result.summary.authors}`);
          console.log(`  Contributors: ${result.summary.contributors}`);
          console.log(`  Subscribers: ${result.summary.subscribers}`);

          // Issues
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
      }

      const hasHighSeverity = (result.bySeverity['HIGH'] || 0) > 0;
      process.exit(hasHighSeverity ? 1 : 0);
      return;
    });
}
