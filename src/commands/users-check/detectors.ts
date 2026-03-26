import {
  WordPressUser,
  UserIssue,
  DEFAULT_ADMIN_LOGIN,
  DEFAULT_ADMIN_EMAIL,
  WP_ROLES,
  ADMIN_ROLES
} from './types';
import { isDisposableEmail, isSpamEmail } from './parsers';

// Check for default admin username
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

// Check for default admin email
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

// Check for multiple admin accounts
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

// Check for unrecognized role assignments
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

// Check for users with no roles assigned
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

// Check for disposable email domains
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

// Check for known spam email domains
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

// Check for inactive users (no login for N days)
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

// Check user status flags (spam, deleted, pending)
export function checkUserStatus(users: WordPressUser[]): UserIssue[] {
  const issues: UserIssue[] = [];

  for (const user of users) {
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

// Run all checks and collect issues
export function runAllUserChecks(users: WordPressUser[]): UserIssue[] {
  const issues: UserIssue[] = [];

  if (users.length === 0) {
    return issues;
  }

  const defaultAdminIssue = checkDefaultAdmin(users);
  if (defaultAdminIssue) {
    issues.push(defaultAdminIssue);
  }

  issues.push(...checkDefaultEmail(users));
  issues.push(...checkMultipleAdmins(users));
  
  // Import detectSuspiciousLogins from parsers
  const { detectSuspiciousLogins } = require('./parsers');
  issues.push(...detectSuspiciousLogins(users));
  
  issues.push(...checkWeakRoleAssignment(users));
  issues.push(...checkNoRole(users));
  issues.push(...checkDisposableEmails(users));
  issues.push(...checkSpamEmails(users));
  issues.push(...checkInactiveUsers(users));
  issues.push(...checkUserStatus(users));

  return issues;
}
