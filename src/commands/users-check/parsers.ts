import * as fs from 'fs';
import * as path from 'path';
import {
  WordPressUser,
  DISPOSABLE_EMAIL_DOMAINS,
  SPAM_EMAIL_DOMAINS
} from './types';

// Email validation functions

export function isDisposableEmail(email: string): boolean {
  const domain = email.split('@')[1]?.toLowerCase();
  if (!domain) return false;
  return DISPOSABLE_EMAIL_DOMAINS.some(d => domain === d || domain.endsWith('.' + d));
}

export function isSpamEmail(email: string): boolean {
  const domain = email.split('@')[1]?.toLowerCase();
  if (!domain) return false;
  return SPAM_EMAIL_DOMAINS.some(d => domain === d || domain.endsWith('.' + d));
}

// Parse PHP stdClass export format (from wp-users.php)
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

// Parse PHP INSERT statements
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

// Parse SQL export with wp_users and wp_usermeta INSERT statements
export function parseSqlExport(content: string): WordPressUser[] {
  const users: WordPressUser[] = [];
  const userRoles: Record<number, string[]> = {};

  // First pass: extract roles from wp_usermeta
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

  // Second pass: extract users from wp_users
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

// Parse wp-config.php for database credentials
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

// Detect suspicious login patterns
export function detectSuspiciousLogins(users: WordPressUser[]): import('./types').UserIssue[] {
  const issues: import('./types').UserIssue[] = [];
  const { SUSPICIOUS_LOGIN_PATTERNS } = require('./types');

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
