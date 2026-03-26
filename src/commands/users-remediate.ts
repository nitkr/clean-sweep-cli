import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import { exec } from 'child_process';
import { detectWordPressRoot, formatWpPathError } from '../wp-path-detector';
import { parseWpConfig } from './db-scan';
import { getLogger } from '../logger';

interface CliOptions {
  dryRun: boolean;
  force: boolean;
  json: boolean;
  path: string;
  verbose: boolean;
}

interface UserInfo {
  id: number;
  login: string;
  email: string;
  roles: string[];
}

function formatOutput(data: unknown, useJson: boolean): void {
  if (useJson) {
    console.log(JSON.stringify(data, null, 2));
  } else if (data && typeof data === 'object' && 'message' in data) {
    console.log((data as { message: string }).message);
  }
}

interface RemediationResult {
  success: boolean;
  dryRun: boolean;
  usersDeleted: number;
  usersSpamFlagged: number;
  orphanedSessionsPurged: number;
  expiredSessionsPurged: number;
  usersMarkedForDeletion: { id: number; login: string; roles: string[] }[];
  usersMarkedForSpamFlag: { id: number; login: string; roles: string[] }[];
  orphanedSessionsUsers: number[];
  expiredSessionsUsers: number[];
  errors: string[];
  backupPath: string | null;
}

function execPromise(cmd: string): Promise<string> {
  return new Promise((resolve, reject) => {
    exec(cmd, { timeout: 60000 }, (error, stdout, stderr) => {
      if (error) {
        reject(new Error(stderr || error.message));
      } else {
        resolve(stdout);
      }
    });
  });
}

async function getUserInfo(
  userId: number,
  credentials: { host: string; name: string; user: string; pass: string; prefix: string }
): Promise<UserInfo | null> {
  const { host, name, user, pass, prefix } = credentials;

  const userQuery = `SELECT user_login, user_email FROM ${prefix}users WHERE ID = ${userId}`;
  const userCmd = `mysql -h "${host}" -u "${user}"${pass ? ` -p"${pass}"` : ''} "${name}" -e "${userQuery}" -B`;

  try {
    const output = await execPromise(userCmd);
    const lines = output.trim().split('\n');
    if (lines.length < 2) return null;

    const fields = lines[1].split('\t');
    if (fields.length < 2) return null;

    const login = fields[0];
    const email = fields[1];

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

    return { id: userId, login, email, roles };
  } catch {
    return null;
  }
}

async function getUsersByIds(
  ids: number[],
  credentials: { host: string; name: string; user: string; pass: string; prefix: string }
): Promise<UserInfo[]> {
  const users: UserInfo[] = [];
  for (const id of ids) {
    const user = await getUserInfo(id, credentials);
    if (user) {
      users.push(user);
    }
  }
  return users;
}

function isAdmin(user: UserInfo, includeAdmins: boolean): boolean {
  if (includeAdmins) return false;
  return user.roles.some(role => role.toLowerCase() === 'administrator');
}

async function createUserBackup(
  users: UserInfo[],
  credentials: { host: string; name: string; user: string; pass: string; prefix: string },
  targetPath: string
): Promise<string> {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupDir = path.join(targetPath, 'clean-sweep-cli', 'backups', `users-${timestamp}`);
  fs.mkdirSync(backupDir, { recursive: true });

  const { host, name, user, pass, prefix } = credentials;

  for (const u of users) {
    const userBackupPath = path.join(backupDir, `user-${u.id}.json`);
    const userQuery = `SELECT * FROM ${prefix}users WHERE ID = ${u.id}`;
    const userCmd = `mysql -h "${host}" -u "${user}"${pass ? ` -p"${pass}"` : ''} "${name}" -e "${userQuery}" -B`;

    const metaQuery = `SELECT * FROM ${prefix}usermeta WHERE user_id = ${u.id}`;
    const metaCmd = `mysql -h "${host}" -u "${user}"${pass ? ` -p"${pass}"` : ''} "${name}" -e "${metaQuery}" -B`;

    try {
      const userData = await execPromise(userCmd);
      const metaData = await execPromise(metaCmd);

      fs.writeFileSync(userBackupPath, JSON.stringify({
        user: u,
        userTableData: userData,
        usermetaData: metaData,
        backupTimestamp: new Date().toISOString(),
      }, null, 2));
    } catch (err) {
      getLogger().warn(`Failed to backup user ${u.id}: ${err}`);
    }
  }

  return backupDir;
}

async function deleteUsers(
  userIds: number[],
  credentials: { host: string; name: string; user: string; pass: string; prefix: string },
  dryRun: boolean,
  backupPath: string | null
): Promise<{ deleted: number; errors: string[] }> {
  const { host, name, user, pass, prefix } = credentials;
  let deleted = 0;
  const errors: string[] = [];

  for (const userId of userIds) {
    if (dryRun) {
      deleted++;
      continue;
    }

    try {
      const postCountQuery = `SELECT COUNT(*) as cnt FROM ${prefix}posts WHERE post_author = ${userId}`;
      const postCountCmd = `mysql -h "${host}" -u "${user}"${pass ? ` -p"${pass}"` : ''} "${name}" -e "${postCountQuery}" -B`;
      const postCountOutput = await execPromise(postCountCmd);
      const postCountLines = postCountOutput.trim().split('\n');
      const postCount = postCountLines.length > 1 ? parseInt(postCountLines[1], 10) : 0;

      if (postCount > 0) {
        const reassignQuery = `UPDATE ${prefix}posts SET post_author = 1 WHERE post_author = ${userId}`;
        const reassignCmd = `mysql -h "${host}" -u "${user}"${pass ? ` -p"${pass}"` : ''} "${name}" -e "${reassignQuery}" -B`;
        await execPromise(reassignCmd);
        getLogger().info(`Reassigned ${postCount} posts from user ${userId} to admin (ID: 1)`);
      }

      const deleteQuery = `DELETE FROM ${prefix}users WHERE ID = ${userId}`;
      const deleteCmd = `mysql -h "${host}" -u "${user}"${pass ? ` -p"${pass}"` : ''} "${name}" -e "${deleteQuery}" -B`;
      await execPromise(deleteCmd);

      getLogger().info(`Deleted user ID: ${userId}`);
      deleted++;
    } catch (err) {
      const errorMsg = `Failed to delete user ${userId}: ${err}`;
      errors.push(errorMsg);
      getLogger().error(errorMsg);
    }
  }

  return { deleted, errors };
}

async function spamFlagUsers(
  userIds: number[],
  credentials: { host: string; name: string; user: string; pass: string; prefix: string },
  dryRun: boolean
): Promise<{ flagged: number; errors: string[] }> {
  const { host, name, user, pass, prefix } = credentials;
  let flagged = 0;
  const errors: string[] = [];

  if (userIds.length === 0) {
    return { flagged: 0, errors: [] };
  }

  const ids = userIds.join(',');

  if (dryRun) {
    flagged = userIds.length;
    return { flagged, errors };
  }

  try {
    const updateQuery = `UPDATE ${prefix}users SET user_status = 1 WHERE ID IN (${ids})`;
    const updateCmd = `mysql -h "${host}" -u "${user}"${pass ? ` -p"${pass}"` : ''} "${name}" -e "${updateQuery}" -B`;
    await execPromise(updateCmd);

    for (const userId of userIds) {
      getLogger().info(`Spam-flagged user ID: ${userId}`);
    }
    flagged = userIds.length;
  } catch (err) {
    const errorMsg = `Failed to spam-flag users: ${err}`;
    errors.push(errorMsg);
    getLogger().error(errorMsg);
  }

  return { flagged, errors };
}

async function purgeOrphanedSessions(
  credentials: { host: string; name: string; user: string; pass: string; prefix: string },
  dryRun: boolean
): Promise<{ purged: number; errors: string[] }> {
  const { host, name, user, pass, prefix } = credentials;
  const errors: string[] = [];

  try {
    const countQuery = `SELECT COUNT(*) as cnt FROM ${prefix}usermeta WHERE meta_key = 'session_tokens' AND user_id NOT IN (SELECT ID FROM ${prefix}users)`;
    const countCmd = `mysql -h "${host}" -u "${user}"${pass ? ` -p"${pass}"` : ''} "${name}" -e "${countQuery}" -B`;
    const countOutput = await execPromise(countCmd);
    const countLines = countOutput.trim().split('\n');
    const orphanedCount = countLines.length > 1 ? parseInt(countLines[1], 10) : 0;

    if (dryRun) {
      return { purged: orphanedCount, errors: [] };
    }

    const deleteQuery = `DELETE FROM ${prefix}usermeta WHERE meta_key = 'session_tokens' AND user_id NOT IN (SELECT ID FROM ${prefix}users)`;
    const deleteCmd = `mysql -h "${host}" -u "${user}"${pass ? ` -p"${pass}"` : ''} "${name}" -e "${deleteQuery}" -B`;
    await execPromise(deleteCmd);

    getLogger().info(`Purged ${orphanedCount} orphaned session tokens`);
    return { purged: orphanedCount, errors: [] };
  } catch (err) {
    const errorMsg = `Failed to purge orphaned sessions: ${err}`;
    errors.push(errorMsg);
    getLogger().error(errorMsg);
    return { purged: 0, errors };
  }
}

function parseSerializedSessionTokens(serialized: string): { token: string; created: number; lastActive: number }[] {
  const sessions: { token: string; created: number; lastActive: number }[] = [];

  try {
    const sessionRegex = /a:\d+:\{[^}]+\}/g;
    const matches = serialized.match(sessionRegex) || [];

    for (const match of matches) {
      const tokenMatch = match.match(/s:10:"token";s:\d+:"([^"]+)"/);
      const createdMatch = match.match(/s:10:"creation";i:(\d+)/);
      const lastActiveMatch = match.match(/s:15:"last_active";i:(\d+)/);

      if (tokenMatch && createdMatch) {
        sessions.push({
          token: tokenMatch[1],
          created: parseInt(createdMatch[1], 10),
          lastActive: lastActiveMatch ? parseInt(lastActiveMatch[1], 10) : parseInt(createdMatch[1], 10),
        });
      }
    }
  } catch {
    // Invalid serialized data
  }

  return sessions;
}

async function purgeExpiredSessions(
  credentials: { host: string; name: string; user: string; pass: string; prefix: string },
  dryRun: boolean,
  daysThreshold: number = 30
): Promise<{ purged: number; errors: string[] }> {
  const { host, name, user, pass, prefix } = credentials;
  const errors: string[] = [];
  const now = Math.floor(Date.now() / 1000);
  const thresholdSeconds = daysThreshold * 24 * 60 * 60;
  let totalExpired = 0;

  try {
    const sessionQuery = `SELECT user_id, meta_value FROM ${prefix}usermeta WHERE meta_key = 'session_tokens'`;
    const sessionCmd = `mysql -h "${host}" -u "${user}"${pass ? ` -p"${pass}"` : ''} "${name}" -e "${sessionQuery}" -B`;

    const output = await execPromise(sessionCmd);
    const lines = output.trim().split('\n').slice(1);

    const userSessionsToUpdate: Map<number, string> = new Map();

    for (const line of lines) {
      const parts = line.split('\t');
      if (parts.length < 2) continue;

      const userId = parseInt(parts[0], 10);
      const serialized = parts[1];

      if (!userId || !serialized) continue;

      const sessions = parseSerializedSessionTokens(serialized);
      const validSessions = sessions.filter(s => (now - s.lastActive) < thresholdSeconds);
      const expiredCount = sessions.length - validSessions.length;

      if (expiredCount > 0 && validSessions.length > 0) {
        totalExpired += expiredCount;

        if (!dryRun) {
          const newSerialized = serializeSessionTokens(validSessions);
          userSessionsToUpdate.set(userId, newSerialized);
        }
      } else if (expiredCount > 0 && validSessions.length === 0) {
        totalExpired += expiredCount;

        if (!dryRun) {
          userSessionsToUpdate.set(userId, 'a:0:{}');
        }
      }
    }

    if (dryRun) {
      return { purged: totalExpired, errors: [] };
    }

    for (const [userId, newSerialized] of userSessionsToUpdate) {
      try {
        const updateQuery = `UPDATE ${prefix}usermeta SET meta_value = '${newSerialized}' WHERE user_id = ${userId} AND meta_key = 'session_tokens'`;
        const updateCmd = `mysql -h "${host}" -u "${user}"${pass ? ` -p"${pass}"` : ''} "${name}" -e "${updateQuery}" -B`;
        await execPromise(updateCmd);
        getLogger().debug(`Purged expired sessions for user ${userId}`);
      } catch (err) {
        getLogger().warn(`Failed to update sessions for user ${userId}: ${err}`);
      }
    }

    if (totalExpired > 0) {
      getLogger().info(`Purged ${totalExpired} expired session tokens`);
    }

    return { purged: totalExpired, errors: [] };
  } catch (err) {
    const errorMsg = `Failed to purge expired sessions: ${err}`;
    errors.push(errorMsg);
    getLogger().error(errorMsg);
    return { purged: 0, errors };
  }
}

function serializeSessionTokens(sessions: { token: string; created: number; lastActive: number }[]): string {
  if (sessions.length === 0) {
    return 'a:0:{}';
  }

  const items = sessions.map(s => {
    const tokenSerialized = `s:10:"token";s:${s.token.length}:"${s.token}"`;
    const creationSerialized = `s:10:"creation";i:${s.created}`;
    const lastActiveSerialized = `s:15:"last_active";i:${s.lastActive}`;
    return `i:${sessions.indexOf(s)};a:3:{${tokenSerialized};${creationSerialized};${lastActiveSerialized}}`;
  }).join('');

  return `a:${sessions.length}:{${items}}`;
}

export function registerUsersRemediateCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  program
    .command('users:remediate')
    .description('Bulk remediation for shadow accounts: delete users, spam-flag, purge sessions')
    .option('--path <path>', 'WordPress installation path')
    .option('--dry-run', 'Preview what would happen without making changes', false)
    .option('--force', 'Actually execute the changes (required)', false)
    .option('--delete-users <ids>', 'Comma-separated user IDs to delete')
    .option('--spam-flag <ids>', 'Comma-separated user IDs to mark as spam')
    .option('--purge-sessions', 'Purge orphaned sessions (sessions for deleted users)', false)
    .option('--purge-expired', 'Purge expired sessions (30+ days old)', false)
    .option('--include-admins', 'Allow deletion/flagging of administrators (DANGEROUS)', false)
    .action(async (cmdOptions) => {
      const opts = getOpts();
      let targetPath = path.resolve(cmdOptions.path || opts.path);
      const useJson = cmdOptions.json || opts.json;

      const dryRun = cmdOptions.dryRun || (opts.dryRun && !cmdOptions.force && !opts.force);
      const force = cmdOptions.force || opts.force;

      if (!dryRun && !force) {
        const error = {
          success: false,
          message: 'This command requires either --dry-run or --force flag.',
        };
        formatOutput(error, useJson);
        process.exit(1);
      }

      if (!fs.existsSync(targetPath)) {
        const error = { success: false, error: 'Path does not exist', path: targetPath };
        formatOutput(error, useJson);
        process.exit(1);
        return;
      }

      const wpResult = detectWordPressRoot(targetPath);
      if (!wpResult.found) {
        const error = { success: false, error: formatWpPathError(wpResult, 'users:remediate'), path: targetPath };
        formatOutput(error, useJson);
        process.exit(1);
        return;
      }
      targetPath = wpResult.path;

      const wpConfigPath = path.join(targetPath, 'wp-config.php');
      const credentials = parseWpConfig(wpConfigPath);

      if (!credentials) {
        const error = { success: false, error: 'Could not parse wp-config.php', path: targetPath };
        formatOutput(error, useJson);
        process.exit(1);
        return;
      }

      const deleteIds = cmdOptions.deleteUsers
        ? cmdOptions.deleteUsers.split(',').map((s: string) => parseInt(s.trim(), 10)).filter((n: number) => !isNaN(n))
        : [];

      const spamFlagIds = cmdOptions.spamFlag
        ? cmdOptions.spamFlag.split(',').map((s: string) => parseInt(s.trim(), 10)).filter((n: number) => !isNaN(n))
        : [];

      const purgeSessions = cmdOptions.purgeSessions || false;
      const purgeExpired = cmdOptions.purgeExpired || false;
      const includeAdmins = cmdOptions.includeAdmins || false;

      const hasActions = deleteIds.length > 0 || spamFlagIds.length > 0 || purgeSessions || purgeExpired;

      if (!hasActions) {
        const error = {
          success: false,
          message: 'No actions specified. Use --delete-users, --spam-flag, --purge-sessions, or --purge-expired.',
        };
        formatOutput(error, useJson);
        process.exit(1);
        return;
      }

      const result: RemediationResult = {
        success: true,
        dryRun,
        usersDeleted: 0,
        usersSpamFlagged: 0,
        orphanedSessionsPurged: 0,
        expiredSessionsPurged: 0,
        usersMarkedForDeletion: [],
        usersMarkedForSpamFlag: [],
        orphanedSessionsUsers: [],
        expiredSessionsUsers: [],
        errors: [],
        backupPath: null,
      };

      const allAffectedUserIds = [...deleteIds, ...spamFlagIds];
      const allAffectedUsers = await getUsersByIds(allAffectedUserIds, credentials);

      const deleteUsersInfo = allAffectedUsers.filter(u => deleteIds.includes(u.id));
      const spamFlagUsersInfo = allAffectedUsers.filter(u => spamFlagIds.includes(u.id));

      const adminDeleteUsers = deleteUsersInfo.filter(u => isAdmin(u, includeAdmins));
      const adminSpamFlagUsers = spamFlagUsersInfo.filter(u => isAdmin(u, includeAdmins));

      if (adminDeleteUsers.length > 0 && !includeAdmins) {
        result.errors.push(`Cannot delete administrators without --include-admins: ${adminDeleteUsers.map(u => `${u.login} (ID:${u.id})`).join(', ')}`);
        result.success = false;
      }

      if (adminSpamFlagUsers.length > 0 && !includeAdmins) {
        result.errors.push(`Cannot spam-flag administrators without --include-admins: ${adminSpamFlagUsers.map(u => `${u.login} (ID:${u.id})`).join(', ')}`);
        result.success = false;
      }

      if (!result.success) {
        formatOutput(result, useJson);
        process.exit(1);
        return;
      }

      const safeDeleteUsers = includeAdmins ? deleteUsersInfo : deleteUsersInfo.filter(u => !isAdmin(u, includeAdmins));
      const safeSpamFlagUsers = includeAdmins ? spamFlagUsersInfo : spamFlagUsersInfo.filter(u => !isAdmin(u, includeAdmins));

      if (safeDeleteUsers.length > 0 && !dryRun) {
        try {
          result.backupPath = await createUserBackup(safeDeleteUsers, credentials, targetPath);
          getLogger().info(`Created user backup at: ${result.backupPath}`);
        } catch (err) {
          result.errors.push(`Failed to create backup: ${err}`);
        }
      }

      if (safeDeleteUsers.length > 0) {
        const deleteResult = await deleteUsers(
          safeDeleteUsers.map(u => u.id),
          credentials,
          dryRun,
          result.backupPath
        );
        result.usersDeleted = deleteResult.deleted;
        result.usersMarkedForDeletion = safeDeleteUsers.map(u => ({ id: u.id, login: u.login, roles: u.roles }));
        result.errors.push(...deleteResult.errors);
      }

      if (safeSpamFlagUsers.length > 0) {
        const spamResult = await spamFlagUsers(
          safeSpamFlagUsers.map(u => u.id),
          credentials,
          dryRun
        );
        result.usersSpamFlagged = spamResult.flagged;
        result.usersMarkedForSpamFlag = safeSpamFlagUsers.map(u => ({ id: u.id, login: u.login, roles: u.roles }));
        result.errors.push(...spamResult.errors);
      }

      if (purgeSessions) {
        const orphanResult = await purgeOrphanedSessions(credentials, dryRun);
        result.orphanedSessionsPurged = orphanResult.purged;
        result.errors.push(...orphanResult.errors);
      }

      if (purgeExpired) {
        const expiredResult = await purgeExpiredSessions(credentials, dryRun);
        result.expiredSessionsPurged = expiredResult.purged;
        result.errors.push(...expiredResult.errors);
      }

      result.success = result.errors.length === 0;

      if (useJson) {
        formatOutput(result, true);
      } else {
        console.log('Clean Sweep User Remediation');
        console.log('========================\n');
        console.log(`Mode: ${dryRun ? 'DRY RUN (no changes made)' : 'FORCE (changes applied)'}\n`);

        if (result.usersMarkedForDeletion.length > 0) {
          console.log('Users marked for deletion:');
          for (const u of result.usersMarkedForDeletion) {
            const roleStr = u.roles.length > 0 ? u.roles.join(', ') : 'none';
            const action = dryRun ? 'Would delete' : 'Deleted';
            console.log(`  ${action} ${u.login} (ID: ${u.id}) - role: ${roleStr}`);
          }
          console.log();
        }

        if (result.usersMarkedForSpamFlag.length > 0) {
          console.log('Users marked for spam-flag:');
          for (const u of result.usersMarkedForSpamFlag) {
            const roleStr = u.roles.length > 0 ? u.roles.join(', ') : 'none';
            const action = dryRun ? 'Would spam-flag' : 'Spam-flagged';
            console.log(`  ${action} ${u.login} (ID: ${u.id}) - role: ${roleStr}`);
          }
          console.log();
        }

        if (purgeSessions) {
          const action = dryRun ? 'Would purge' : 'Purged';
          console.log(`${action} ${result.orphanedSessionsPurged} orphaned session(s)\n`);
        }

        if (purgeExpired) {
          const action = dryRun ? 'Would purge' : 'Purged';
          console.log(`${action} ${result.expiredSessionsPurged} expired session(s)\n`);
        }

        if (result.errors.length > 0) {
          console.log('Errors:');
          for (const err of result.errors) {
            console.log(`  - ${err}`);
          }
          console.log();
        }

        if (result.backupPath) {
          console.log(`Backup created at: ${result.backupPath}\n`);
        }

        console.log(`[${dryRun ? 'DRY RUN' : 'FORCE'}] ${dryRun ? 'No changes made. Use --force to execute.' : 'Changes have been applied.'}`);
      }

      process.exit(result.success ? 0 : 1);
    });
}
