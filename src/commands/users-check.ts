// Re-export from modular users-check/ directory
// This file exists for backward compatibility

export {
  registerUsersCheckCommand,
  checkUsers,
  checkUsersFromDatabase,
  WordPressUser,
  UserIssue,
  UsersCheckResult,
  CliOptions
} from './users-check/index';

// Re-export types
export {
  DEFAULT_ADMIN_LOGIN,
  DEFAULT_ADMIN_EMAIL,
  DISPOSABLE_EMAIL_DOMAINS,
  SPAM_EMAIL_DOMAINS,
  SUSPICIOUS_LOGIN_PATTERNS,
  WP_ROLES,
  ADMIN_ROLES
} from './users-check/types';

// Re-export parsers
export {
  isDisposableEmail,
  isSpamEmail,
  parsePhpUsersExport,
  parseSqlExport,
  parseWpConfig,
  DbCredentials,
  detectSuspiciousLogins
} from './users-check/parsers';

// Re-export detectors
export {
  checkDefaultAdmin,
  checkDefaultEmail,
  checkMultipleAdmins,
  checkWeakRoleAssignment,
  checkNoRole,
  checkDisposableEmails,
  checkSpamEmails,
  checkInactiveUsers,
  checkUserStatus,
  runAllUserChecks
} from './users-check/detectors';

// Re-export db
export {
  execPromise,
  queryDatabase
} from './users-check/db';
