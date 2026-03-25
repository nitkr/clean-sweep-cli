import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import { exec } from 'child_process';
import { detectWordPressRoot, formatWpPathError } from '../wp-path-detector';
import { parseWpConfig } from './db-scan';

interface CliOptions {
  dryRun: boolean;
  force: boolean;
  json: boolean;
  path: string;
  verbose: boolean;
}

interface WordPressUser {
  id: number;
  login: string;
  email: string;
  displayName: string;
  roles: string[];
  registeredDate?: string;
  lastLoginDate?: string;
}

interface CleanupResult {
  path: string;
  success: boolean;
  usersFound: number;
  usersToDelete: number;
  usersDeleted: number;
  deletedUsers: { id: number; login: string; reason: string }[];
  errors: string[];
  dryRun: boolean;
}

function formatOutput(data: unknown, useJson: boolean): void {
  if (useJson) {
    console.log(JSON.stringify(data, null, 2));
  }
}

async function execPromise(cmd: string): Promise<string> {
  return new Promise((resolve, reject) => {
    exec(cmd, { timeout: 30000 }, (error, stdout, stderr) => {
      if (error) {
        reject(new Error(stderr || error.message));
      } else {
        resolve(stdout);
      }
    });
  });
}

export function registerUsersCleanupCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  program
    .command('users:cleanup')
    .description('Identify and remove inactive WordPress accounts')
    .option('--path <path>', 'WordPress installation path')
    .option('--days <days>', 'Inactive threshold in days (default: 90)', '90')
    .option('--roles <roles>', 'Comma-separated roles to consider (default: subscriber,contributor)', 'subscriber,contributor')
    .option('--reassign <user_id>', 'User ID to reassign posts to before deletion')
    .option('--dry-run', 'Preview what would be deleted without actually deleting', false)
    .option('--force', 'Actually perform the deletion', false)
    .action(async (cmdOptions) => {
      const opts = getOpts();
      let targetPath = path.resolve(cmdOptions.path || opts.path);
      const useJson = cmdOptions.json || opts.json;
      const dryRun = cmdOptions.dryRun || opts.dryRun;
      const force = cmdOptions.force || opts.force;

      if (!fs.existsSync(targetPath)) {
        const error = { success: false, error: 'Path does not exist', path: targetPath };
        formatOutput(error, useJson);
        process.exit(1);
        return;
      }

      const wpResult = detectWordPressRoot(targetPath);
      if (!wpResult.found) {
        const error = { success: false, error: formatWpPathError(wpResult, 'users:cleanup'), path: targetPath };
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

      const daysThreshold = parseInt(cmdOptions.days || '90', 10);
      const rolesToCleanup = (cmdOptions.roles || 'subscriber,contributor').split(',').map((r: string) => r.trim());
      const reassignUserId = cmdOptions.reassign ? parseInt(cmdOptions.reassign, 10) : null;

      if (!useJson) {
        console.log(`Scanning for inactive users in: ${targetPath}`);
        console.log(`Inactive threshold: ${daysThreshold} days`);
        console.log(`Roles to consider: ${rolesToCleanup.join(', ')}`);
        if (reassignUserId) {
          console.log(`Posts will be reassigned to user ID: ${reassignUserId}`);
        }
      }

      try {
        const result = await cleanupInactiveUsers(
          targetPath,
          credentials,
          daysThreshold,
          rolesToCleanup,
          reassignUserId,
          dryRun,
          force
        );

        if (!useJson) {
          console.log('\n--- Cleanup Results ---');
          console.log(`Users found: ${result.usersFound}`);
          console.log(`Users to delete: ${result.usersToDelete}`);

          if (dryRun) {
            console.log(`\n[DRY RUN] Would delete ${result.usersDeleted} user(s)`);
          } else {
            console.log(`Users deleted: ${result.usersDeleted}`);
          }

          if (result.deletedUsers.length > 0) {
            console.log('\nDeleted users:');
            for (const user of result.deletedUsers) {
              console.log(`  - ${user.login} (ID: ${user.id}): ${user.reason}`);
            }
          }

          if (result.errors.length > 0) {
            console.log('\nErrors:');
            for (const err of result.errors) {
              console.log(`  - ${err}`);
            }
          }
        }

        formatOutput(result, useJson);

        if (!dryRun && result.errors.length > 0) {
          process.exit(1);
        }
      } catch (err) {
        const error = {
          success: false,
          error: String(err),
          dryRun,
        };
        formatOutput(error, useJson);
        process.exit(1);
      }
    });
}

async function cleanupInactiveUsers(
  targetPath: string,
  credentials: { host: string; name: string; user: string; pass: string; prefix: string },
  daysThreshold: number,
  rolesToCleanup: string[],
  reassignUserId: number | null,
  dryRun: boolean,
  force: boolean
): Promise<CleanupResult> {
  const result: CleanupResult = {
    path: targetPath,
    success: true,
    usersFound: 0,
    usersToDelete: 0,
    usersDeleted: 0,
    deletedUsers: [],
    errors: [],
    dryRun,
  };

  const { host, name, user, pass, prefix } = credentials;
  const now = new Date();
  const thresholdMs = daysThreshold * 24 * 60 * 60 * 1000;

  // Query all users from database
  const userQuery = `SELECT ID, user_login, user_email, display_name, user_registered FROM ${prefix}users ORDER BY ID`;
  const userCmd = `mysql -h "${host}" -u "${user}"${pass ? ` -p"${pass}"` : ''} "${name}" -e "${userQuery}" -B`;

  let userOutput: string;
  try {
    userOutput = await execPromise(userCmd);
  } catch (err) {
    result.errors.push(`Failed to query users: ${err}`);
    result.success = false;
    return result;
  }

  const userLines = userOutput.trim().split('\n').slice(1);
  const users: WordPressUser[] = [];

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

        users.push({
          id: userId,
          login: fields[1],
          email: fields[2],
          displayName: fields[3] || fields[1],
          roles,
          registeredDate: fields[4],
        });
      }
    }
  }

  result.usersFound = users.length;

  // Filter inactive users
  const inactiveUsers: WordPressUser[] = [];
  for (const user of users) {
    // Skip administrators
    if (user.roles.includes('administrator')) {
      continue;
    }

    // Check if role is in cleanup list
    const hasCleanupRole = user.roles.some(role => rolesToCleanup.includes(role.toLowerCase()));
    if (!hasCleanupRole) {
      continue;
    }

    // Check last login or registration date
    if (user.lastLoginDate) {
      const lastLogin = new Date(user.lastLoginDate);
      const inactiveMs = now.getTime() - lastLogin.getTime();
      if (inactiveMs > thresholdMs) {
        inactiveUsers.push(user);
      }
    } else if (user.registeredDate) {
      // Fallback to registration date if no last login data
      const registered = new Date(user.registeredDate);
      const inactiveMs = now.getTime() - registered.getTime();
      if (inactiveMs > thresholdMs) {
        inactiveUsers.push(user);
      }
    }
  }

  result.usersToDelete = inactiveUsers.length;

  // Check if we can safely delete
  if (inactiveUsers.length > 0 && !reassignUserId && !dryRun) {
    result.errors.push('Cannot delete users without --reassign option. Posts would be orphaned. Use --dry-run to preview.');
    result.success = false;
    return result;
  }

  if (!force && !dryRun) {
    result.errors.push('Must pass --force to actually delete users. Use --dry-run to preview first.');
    result.success = false;
    return result;
  }

  // Delete inactive users
  for (const user of inactiveUsers) {
    if (dryRun) {
      result.deletedUsers.push({
        id: user.id,
        login: user.login,
        reason: `Inactive for ${daysThreshold}+ days`,
      });
      result.usersDeleted++;
    } else {
      try {
        // Check if user has posts
        const postCountQuery = `SELECT COUNT(*) as cnt FROM ${prefix}posts WHERE post_author = ${user.id}`;
        const postCountCmd = `mysql -h "${host}" -u "${user}"${pass ? ` -p"${pass}"` : ''} "${name}" -e "${postCountQuery}" -B`;
        const postCountOutput = await execPromise(postCountCmd);
        const postCountLines = postCountOutput.trim().split('\n');
        const postCount = postCountLines.length > 1 ? parseInt(postCountLines[1], 10) : 0;

        if (postCount > 0 && reassignUserId) {
          // Reassign posts first
          const reassignQuery = `UPDATE ${prefix}posts SET post_author = ${reassignUserId} WHERE post_author = ${user.id}`;
          const reassignCmd = `mysql -h "${host}" -u "${user}"${pass ? ` -p"${pass}"` : ''} "${name}" -e "${reassignQuery}" -B`;
          await execPromise(reassignCmd);
        }

        // Delete user (usermeta cascades automatically)
        const deleteQuery = `DELETE FROM ${prefix}users WHERE ID = ${user.id}`;
        const deleteCmd = `mysql -h "${host}" -u "${user}"${pass ? ` -p"${pass}"` : ''} "${name}" -e "${deleteQuery}" -B`;
        await execPromise(deleteCmd);

        result.deletedUsers.push({
          id: user.id,
          login: user.login,
          reason: `Deleted (had ${postCount} posts${reassignUserId ? ', reassigned' : ''})`,
        });
        result.usersDeleted++;
      } catch (err) {
        result.errors.push(`Failed to delete user ${user.login} (ID: ${user.id}): ${err}`);
        // Don't fall through - if an error occurred, don't mark as deleted
      }
    }
  }

  return result;
}