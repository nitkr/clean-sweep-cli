// Interfaces for WordPress user data structures

export interface CliOptions {
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

// Constants for user detection

export const DEFAULT_ADMIN_LOGIN = 'admin';
export const DEFAULT_ADMIN_EMAIL = 'admin@example.com';

// Disposable email domains that should be flagged
export const DISPOSABLE_EMAIL_DOMAINS = [
  'mailinator.com', 'tempmail.com', '10minutemail.com', 'guerrillamail.com',
  'throwaway.email', 'temp-mail.org', 'fakeinbox.com', 'trashmail.com',
  'maildrop.cc', 'getnada.com', 'mohmal.com', 'tempail.com', 'discard.email',
  'sharklasers.com', 'grr.la', 'guerrillamailblock.com', 'pokemail.net',
  'spam4.me', 'tempinbox.com', 'yopmail.com', 'getairmail.com'
];

// Known spam/malicious email domains
export const SPAM_EMAIL_DOMAINS = [
  'spam.com', 'spammer.com', 'junkmail.com', 'tempmailaddress.com'
];

// Suspicious login name patterns
export const SUSPICIOUS_LOGIN_PATTERNS = [
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

// WordPress roles
export const WP_ROLES = ['administrator', 'editor', 'author', 'contributor', 'subscriber'];
export const ADMIN_ROLES = ['administrator'];
