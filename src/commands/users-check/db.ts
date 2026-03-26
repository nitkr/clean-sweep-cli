import { exec } from 'child_process';
import * as path from 'path';
import { WordPressUser } from './types';
import { parseWpConfig, DbCredentials } from './parsers';

// Execute shell command and return promise
export function execPromise(command: string): Promise<string> {
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

// Query WordPress database for users
export async function queryDatabase(wpPath: string): Promise<WordPressUser[]> {
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
