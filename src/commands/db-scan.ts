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

export interface DbCredentials {
  host: string;
  name: string;
  user: string;
  pass: string;
  prefix: string;
}

interface DbThreat {
  table: string;
  column: string;
  rowId: number;
  type: string;
  content: string;
}

interface DbScanResult {
  success: boolean;
  scannedTables: string[];
  threats: DbThreat[];
  dryRun: boolean;
}

function formatOutput(data: unknown, useJson: boolean): void {
  if (useJson) {
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(data);
  }
}

const DB_SUSPICIOUS_PATTERNS = [
  { pattern: /eval\s*\(/gi, type: 'eval_statement' },
  { pattern: /base64_decode\s*\(/gi, type: 'base64_decode' },
  { pattern: /base64_encode\s*\(/gi, type: 'base64_encode' },
  { pattern: /<iframe/gi, type: 'iframe_tag' },
  { pattern: /<script/gi, type: 'script_tag' },
  { pattern: /javascript:/gi, type: 'javascript_protocol' },
  { pattern: /on(load|error|click|mouse)/gi, type: 'event_handler' },
  { pattern: /wp-embed\.php/gi, type: 'wp_embed' },
  { pattern: /\.xyz|\.top|\.gq|\.tk|\.ml|\.cf|\.ga/gi, type: 'suspicious_tld' },
  { pattern: /(?:https?:\/\/)?[a-z0-9-]+\.(?:xyz|top|gq|tk|ml|cf|ga)(?:\/|$)/gi, type: 'suspicious_domain' },
  { pattern: /\$_(GET|POST|REQUEST)\[/gi, type: 'user_input_access' },
  { pattern: /shell_exec|system\(|exec\(|passthru\(/gi, type: 'shell_command' },
  { pattern: /preg_replace.*\/e/gi, type: 'preg_replace_eval' },
  { pattern: /gzinflate\s*\(/gi, type: 'gzinflate' },
  { pattern: /str_rot13\s*\(/gi, type: 'str_rot13' },
  { pattern: /chr\s*\(\s*\d+\s*\)\s*\./gi, type: 'char_obfuscation' },
  { pattern: /assert\s*\(/gi, type: 'assert_statement' },
  { pattern: /preg_replace\s*\(/gi, type: 'preg_replace' },
  { pattern: /create_function\s*\(/gi, type: 'create_function' },
  { pattern: /call_user_func\s*\(/gi, type: 'call_user_func' },
  { pattern: /array_map\s*\([^,]+,\s*/gi, type: 'array_map_callable' },
  { pattern: /\.xyz(?:\/|$|\?)/gi, type: 'xyz_domain' },
  { pattern: /\.top(?:\/|$|\?)/gi, type: 'top_domain' },
  { pattern: /\.work(?:\/|$|\?)/gi, type: 'work_domain' },
  { pattern: /\.click(?:\/|$|\?)/gi, type: 'click_domain' },
  { pattern: /urlencode\s*\(/gi, type: 'urlencode' },
  { pattern: /rawurlencode\s*\(/gi, type: 'rawurlencode' },
];

export function parseWpConfig(wpConfigPath: string): DbCredentials | null {
  if (!fs.existsSync(wpConfigPath)) {
    return null;
  }

  const content = fs.readFileSync(wpConfigPath, 'utf-8');
  
  const extractConstant = (name: string): string | null => {
    const regex = new RegExp(`define\\s*\\(\\s*['"]${name}['"]\\s*,\\s*['"]([^'"]*)['"]\\s*\\)`, 'i');
    const match = content.match(regex);
    return match ? match[1] : null;
  };

  const extractPrefix = (): string => {
    const regex = /\$table_prefix\s*=\s*['"]([^'"]*)['"]/;
    const match = content.match(regex);
    return match ? match[1] : 'wp_';
  };

  const host = extractConstant('DB_HOST') || 'localhost';
  const name = extractConstant('DB_NAME');
  const user = extractConstant('DB_USER');
  const pass = extractConstant('DB_PASSWORD');
  const prefix = extractPrefix();

  if (!name || !user) {
    return null;
  }

  return { host, name, user, pass: pass || '', prefix };
}

async function runMysqlQuery(credentials: DbCredentials, query: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const cmd = `mysql -h "${credentials.host}" -u "${credentials.user}"${credentials.pass ? ` -p"${credentials.pass}"` : ''} "${credentials.name}" -e "${query.replace(/"/g, '\\"')}" 2>/dev/null`;
    
    exec(cmd, { timeout: 30000 }, (error, stdout, stderr) => {
      if (error) {
        reject(error);
      } else {
        resolve(stdout);
      }
    });
  });
}

export function parseMysqlOutput(output: string): { id: number; content: string }[] {
  const lines = output.trim().split('\n');
  if (lines.length < 2) return [];
  
  const results: { id: number; content: string }[] = [];
  const headers = lines[0].toLowerCase().split('\t');
  const idIndex = headers.indexOf('id');
  const valueIndex = headers.length > 1 ? 1 : 0;
  
  for (let i = 1; i < lines.length; i++) {
    const parts = lines[i].split('\t');
    if (parts.length > valueIndex) {
      const id = idIndex >= 0 ? parseInt(parts[idIndex], 10) : i;
      results.push({ id, content: parts[valueIndex] || '' });
    }
  }
  
  return results;
}

async function scanDbTable(
  credentials: DbCredentials,
  table: string,
  column: string,
  dryRun: boolean,
  useJson: boolean
): Promise<DbThreat[]> {
  const threats: DbThreat[] = [];
  
  for (const pattern of DB_SUSPICIOUS_PATTERNS) {
    const escapedPattern = pattern.pattern.source.replace(/'/g, "''");
    const query = `SELECT ID, ${column} FROM ${table} WHERE ${column} LIKE '%${escapedPattern}%' LIMIT 100`;
    
    if (dryRun) {
      if (!useJson) {
        console.log(`[DRY RUN] Would execute: ${query}`);
      }
      continue;
    }
    
    try {
      const output = await runMysqlQuery(credentials, query);
      const results = parseMysqlOutput(output);
      
      for (const result of results) {
        threats.push({
          table,
          column,
          rowId: result.id,
          type: pattern.type,
          content: result.content.substring(0, 200),
        });
      }
    } catch {
      // Skip queries that fail
    }
  }
  
  return threats;
}

async function scanDatabase(
  targetPath: string,
  options: { dryRun: boolean; dbHost?: string; dbName?: string; dbUser?: string; dbPass?: string; useJson?: boolean }
): Promise<DbScanResult> {
  const wpConfigPath = path.join(targetPath, 'wp-config.php');
  const credentials = parseWpConfig(wpConfigPath);
  
  let dbCredentials: DbCredentials;
  
  if (options.dbHost && options.dbName && options.dbUser) {
    dbCredentials = {
      host: options.dbHost,
      name: options.dbName,
      user: options.dbUser,
      pass: options.dbPass || '',
      prefix: credentials?.prefix || 'wp_',
    };
  } else if (credentials) {
    dbCredentials = credentials;
  } else {
    throw new Error('Database credentials not found. Provide --db-host, --db-name, --db-user, --db-pass or ensure wp-config.php exists.');
  }
  
  const tables = [
    { name: `${dbCredentials.prefix}posts`, column: 'post_content' },
    { name: `${dbCredentials.prefix}postmeta`, column: 'meta_value' },
    { name: `${dbCredentials.prefix}comments`, column: 'comment_content' },
    { name: `${dbCredentials.prefix}commentmeta`, column: 'meta_value' },
    { name: `${dbCredentials.prefix}options`, column: 'option_value' },
    { name: `${dbCredentials.prefix}users`, column: 'user_pass' },
    { name: `${dbCredentials.prefix}usermeta`, column: 'meta_value' },
    { name: `${dbCredentials.prefix}terms`, column: 'name' },
    { name: `${dbCredentials.prefix}term_taxonomy`, column: 'description' },
    { name: `${dbCredentials.prefix}links`, column: 'link_description' },
  ];
  
  const scannedTables: string[] = [];
  const allThreats: DbThreat[] = [];
  
  for (const table of tables) {
    scannedTables.push(table.name);
    
    if (options.dryRun) {
      if (!options.useJson) {
        console.log(`\n[DRY RUN] Would scan table: ${table.name}`);
        for (const pattern of DB_SUSPICIOUS_PATTERNS.slice(0, 3)) {
          console.log(`[DRY RUN]   Pattern: ${pattern.type}`);
        }
        console.log(`[DRY RUN]   Query example: SELECT ID, ${table.column} FROM ${table.name} WHERE ${table.column} LIKE '%pattern%'`);
      }
    } else {
      const threats = await scanDbTable(dbCredentials, table.name, table.column, false, options.useJson ?? false);
      allThreats.push(...threats);
    }
  }
  
  if (options.dryRun && !options.useJson) {
    console.log(`\n[DRY RUN] MySQL client check:`);
    exec('which mysql', (error) => {
      if (error) {
        console.log(`[DRY RUN] WARNING: mysql command-line client not found in PATH`);
        console.log(`[DRY RUN] Install with: apt-get install mysql-client or yum install mysql`);
      } else {
        console.log(`[DRY RUN] mysql client found`);
      }
    });
  }
  
  return {
    success: true,
    scannedTables,
    threats: options.dryRun ? [] : allThreats,
    dryRun: options.dryRun,
  };
}

export function registerDbScanCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  program
    .command('db:scan')
    .description('Scan WordPress database tables for suspicious content')
    .option('--path <path>', 'WordPress installation path')
    .option('--db-host <host>', 'Database host (optional if wp-config.php exists)')
    .option('--db-name <name>', 'Database name (optional if wp-config.php exists)')
    .option('--db-user <user>', 'Database user (optional if wp-config.php exists)')
    .option('--db-pass <pass>', 'Database password (optional if wp-config.php exists)')
    .option('--dry-run', 'Preview SQL queries without executing', false)
    .option('--force', 'Actually execute the scan', false)
    .action(async (cmdOptions) => {
      const opts = getOpts();
      let targetPath = cmdOptions.path || opts.path;
      const dryRun = (cmdOptions.dryRun || opts.dryRun) && !(cmdOptions.force || opts.force);

      const normalizedPath = path.resolve(targetPath);

      if (!fs.existsSync(normalizedPath)) {
        const error = { success: false, error: 'Path does not exist', path: normalizedPath };
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      }

      let wpResult;
      if (!cmdOptions.path && opts.path === process.cwd()) {
        wpResult = detectWordPressRoot(targetPath);
        if (wpResult.found) {
          targetPath = wpResult.path;
        }
      } else {
        const wpConfigPath = path.join(normalizedPath, 'wp-config.php');
        if (fs.existsSync(wpConfigPath)) {
          wpResult = { path: normalizedPath, found: true, searchedPaths: [normalizedPath] };
          targetPath = normalizedPath;
        } else {
          wpResult = { path: normalizedPath, found: false, searchedPaths: [normalizedPath] };
        }
      }

      if (!wpResult.found && !cmdOptions.dbHost) {
        const error = {
          success: false,
          error: formatWpPathError(wpResult, 'db:scan'),
          path: normalizedPath,
        };
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      }
      
      const wpConfigPath = path.join(targetPath, 'wp-config.php');
      if (!fs.existsSync(wpConfigPath) && !cmdOptions.dbHost) {
        const error = { 
          success: false, 
          error: 'wp-config.php not found and database parameters not provided',
          path: targetPath,
        };
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      }
      
      try {
        const result = await scanDatabase(targetPath, {
          dryRun,
          dbHost: cmdOptions.dbHost,
          dbName: cmdOptions.dbName,
          dbUser: cmdOptions.dbUser,
          dbPass: cmdOptions.dbPass,
          useJson: opts.json || cmdOptions.json,
        });
        
        if (!opts.json && !cmdOptions.json) {
          console.log(`\nDatabase scan completed`);
          console.log(`Scanned tables: ${result.scannedTables.join(', ')}`);
          
          if (dryRun) {
            console.log(`Mode: DRY RUN (use --force to execute)`);
          } else {
            console.log(`Threats found: ${result.threats.length}`);
            
            if (result.threats.length > 0) {
              console.log(`\nThreat details:`);
              const byType: Record<string, number> = {};
              for (const threat of result.threats) {
                byType[threat.type] = (byType[threat.type] || 0) + 1;
              }
              for (const [type, count] of Object.entries(byType)) {
                console.log(`  - ${type}: ${count}`);
              }
            }
          }
        } else {
          formatOutput(result, opts.json || cmdOptions.json);
        }
      } catch (err) {
        const error = { 
          success: false, 
          error: String(err),
          dryRun,
        };
        if (opts.json || cmdOptions.json) {
          formatOutput(error, opts.json || cmdOptions.json);
        } else {
          console.error(`\nError: ${error.error}`);
        }
        process.exit(1);
      }
    });
}
