import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import { exec } from 'child_process';
import { parseWpConfig, DbCredentials } from './db-scan';
import { detectWordPressRoot, formatWpPathError } from '../wp-path-detector';

interface CliOptions {
  dryRun: boolean;
  force: boolean;
  json: boolean;
  path: string;
  verbose: boolean;
}

interface OptimizationTask {
  table: string;
  action: string;
  query: string;
  savingsEstimate: string;
}

interface OptimizationResult {
  success: boolean;
  prefix: string;
  dryRun: boolean;
  tasks: OptimizationTask[];
  scriptPath?: string;
  summary: {
    tablesAffected: number;
    totalTasks: number;
  };
}

function formatOutput(data: unknown, useJson: boolean): void {
  if (useJson) {
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(data);
  }
}

export function generateOptimizationQueries(prefix: string): OptimizationTask[] {
  const tasks: OptimizationTask[] = [];

  // 1. Delete post revisions
  tasks.push({
    table: `${prefix}posts`,
    action: 'delete_post_revisions',
    query: `DELETE FROM ${prefix}posts WHERE post_type = 'revision';`,
    savingsEstimate: 'Variable based on revision count',
  });

  // 2. Delete auto-drafts
  tasks.push({
    table: `${prefix}posts`,
    action: 'delete_auto_drafts',
    query: `DELETE FROM ${prefix}posts WHERE post_status = 'auto-draft';`,
    savingsEstimate: 'Small',
  });

  // 3. Delete trashed posts
  tasks.push({
    table: `${prefix}posts`,
    action: 'delete_trashed_posts',
    query: `DELETE FROM ${prefix}posts WHERE post_status = 'trash';`,
    savingsEstimate: 'Variable',
  });

  // 4. Delete orphaned post meta (meta with no matching post)
  tasks.push({
    table: `${prefix}postmeta`,
    action: 'delete_orphaned_postmeta',
    query: `DELETE pm FROM ${prefix}postmeta pm LEFT JOIN ${prefix}posts p ON pm.post_id = p.ID WHERE p.ID IS NULL;`,
    savingsEstimate: 'Variable based on orphan count',
  });

  // 5. Delete orphaned comment meta
  tasks.push({
    table: `${prefix}commentmeta`,
    action: 'delete_orphaned_commentmeta',
    query: `DELETE cm FROM ${prefix}commentmeta cm LEFT JOIN ${prefix}comments c ON cm.comment_id = c.comment_ID WHERE c.comment_ID IS NULL;`,
    savingsEstimate: 'Small',
  });

  // 6. Delete trashed comments
  tasks.push({
    table: `${prefix}comments`,
    action: 'delete_trashed_comments',
    query: `DELETE FROM ${prefix}comments WHERE comment_approved = 'trash';`,
    savingsEstimate: 'Small',
  });

  // 7. Delete spam comments
  tasks.push({
    table: `${prefix}comments`,
    action: 'delete_spam_comments',
    query: `DELETE FROM ${prefix}comments WHERE comment_approved = 'spam';`,
    savingsEstimate: 'Variable based on spam count',
  });

  // 8. Delete orphaned comment meta (for spam/trashed)
  tasks.push({
    table: `${prefix}commentmeta`,
    action: 'delete_spam_commentmeta',
    query: `DELETE cm FROM ${prefix}commentmeta cm LEFT JOIN ${prefix}comments c ON cm.comment_id = c.comment_ID WHERE c.comment_ID IS NULL;`,
    savingsEstimate: 'Small',
  });

  // 9. Delete expired transients
  tasks.push({
    table: `${prefix}options`,
    action: 'delete_expired_transients',
    query: `DELETE FROM ${prefix}options WHERE option_name LIKE '_transient_timeout_%' AND option_value < UNIX_TIMESTAMP();`,
    savingsEstimate: 'Variable',
  });

  // 10. Delete transient options themselves
  tasks.push({
    table: `${prefix}options`,
    action: 'delete_orphaned_transients',
    query: `DELETE FROM ${prefix}options WHERE option_name LIKE '_transient_%' AND option_name NOT LIKE '_transient_timeout_%' AND option_name NOT IN (SELECT CONCAT('_transient_timeout_', SUBSTRING(option_name, 13)) FROM ${prefix}options WHERE option_name LIKE '_transient_timeout_%');`,
    savingsEstimate: 'Variable',
  });

  // 11. Delete orphaned term relationships
  tasks.push({
    table: `${prefix}term_relationships`,
    action: 'delete_orphaned_term_relationships',
    query: `DELETE tr FROM ${prefix}term_relationships tr LEFT JOIN ${prefix}posts p ON tr.object_id = p.ID WHERE p.ID IS NULL AND tr.term_taxonomy_id != 1;`,
    savingsEstimate: 'Small',
  });

  // 12. Delete unused terms (not in term_taxonomy)
  tasks.push({
    table: `${prefix}terms`,
    action: 'delete_unused_terms',
    query: `DELETE t FROM ${prefix}terms t LEFT JOIN ${prefix}term_taxonomy tt ON t.term_id = tt.term_id WHERE tt.term_id IS NULL;`,
    savingsEstimate: 'Small',
  });

  // 13. Optimize tables
  const tablesToOptimize = [
    `${prefix}posts`,
    `${prefix}postmeta`,
    `${prefix}comments`,
    `${prefix}commentmeta`,
    `${prefix}options`,
    `${prefix}terms`,
    `${prefix}term_taxonomy`,
    `${prefix}term_relationships`,
    `${prefix}users`,
    `${prefix}usermeta`,
  ];

  for (const table of tablesToOptimize) {
    tasks.push({
      table,
      action: 'optimize',
      query: `OPTIMIZE TABLE ${table};`,
      savingsEstimate: 'Reclaims unused space',
    });
  }

  return tasks;
}

export function generateOptimizationScript(tasks: OptimizationTask[], dbCredentials: DbCredentials): string {
  const lines: string[] = [];
  lines.push('#!/usr/bin/env bash');
  lines.push('# WordPress Database Optimization Script');
  lines.push('# Generated by clean-sweep db:optimize');
  lines.push(`# Date: ${new Date().toISOString()}`);
  lines.push('');
  lines.push('set -euo pipefail');
  lines.push('');
  lines.push(`DB_HOST="${dbCredentials.host}"`);
  lines.push(`DB_NAME="${dbCredentials.name}"`);
  lines.push(`DB_USER="${dbCredentials.user}"`);
  lines.push(`DB_PASS="${dbCredentials.pass}"`);
  lines.push('');
  lines.push('MYSQL_CMD="mysql -h $DB_HOST -u $DB_USER -p$DB_PASS $DB_NAME"');
  lines.push('');
  lines.push('echo "Starting WordPress database optimization..."');
  lines.push('');

  for (let i = 0; i < tasks.length; i++) {
    const task = tasks[i];
    lines.push(`# Task ${i + 1}: ${task.action} on ${task.table}`);
    lines.push(`echo "[${i + 1}/${tasks.length}] ${task.action}..."`);
    lines.push(`$MYSQL_CMD -e "${task.query.replace(/"/g, '\\"')}"`);
    lines.push('');
  }

  lines.push('echo "Optimization complete."');
  return lines.join('\n');
}

async function runOptimization(
  targetPath: string,
  options: { dryRun: boolean; dbHost?: string; dbName?: string; dbUser?: string; dbPass?: string }
): Promise<OptimizationResult> {
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

  const tasks = generateOptimizationQueries(dbCredentials.prefix);

  if (options.dryRun) {
    return {
      success: true,
      prefix: dbCredentials.prefix,
      dryRun: true,
      tasks,
      summary: {
        tablesAffected: new Set(tasks.map(t => t.table)).size,
        totalTasks: tasks.length,
      },
    };
  }

  const scriptDir = path.join(targetPath, 'wp-content');
  const scriptPath = path.join(scriptDir, `db-optimize-${Date.now()}.sh`);

  if (fs.existsSync(scriptDir)) {
    const script = generateOptimizationScript(tasks, dbCredentials);
    fs.writeFileSync(scriptPath, script, { mode: 0o700 });
  }

  return {
    success: true,
    prefix: dbCredentials.prefix,
    dryRun: false,
    tasks,
    scriptPath: fs.existsSync(scriptDir) ? scriptPath : undefined,
    summary: {
      tablesAffected: new Set(tasks.map(t => t.table)).size,
      totalTasks: tasks.length,
    },
  };
}

export function registerDbOptimizeCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  program
    .command('db:optimize')
    .description('Generate WordPress database optimization queries and scripts')
    .option('--path <path>', 'WordPress installation path')
    .option('--db-host <host>', 'Database host (optional if wp-config.php exists)')
    .option('--db-name <name>', 'Database name (optional if wp-config.php exists)')
    .option('--db-user <user>', 'Database user (optional if wp-config.php exists)')
    .option('--db-pass <pass>', 'Database password (optional if wp-config.php exists)')
    .option('--dry-run', 'Preview optimization queries without executing', false)
    .option('--force', 'Generate optimization script and skip dry-run', false)
    .action(async (cmdOptions) => {
      const opts = getOpts();
      let targetPath = path.resolve(cmdOptions.path || opts.path);
      const dryRun = (cmdOptions.dryRun || opts.dryRun) && !(cmdOptions.force || opts.force);

      if (!fs.existsSync(targetPath)) {
        const error = { success: false, error: 'Path does not exist', path: targetPath };
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      }

      const wpResult = detectWordPressRoot(targetPath);
      if (!wpResult.found && !cmdOptions.dbHost) {
        const error = {
          success: false,
          error: formatWpPathError(wpResult, 'db:optimize'),
          path: targetPath,
        };
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      }
      if (wpResult.found) {
        targetPath = wpResult.path;
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
        const result = await runOptimization(targetPath, {
          dryRun,
          dbHost: cmdOptions.dbHost,
          dbName: cmdOptions.dbName,
          dbUser: cmdOptions.dbUser,
          dbPass: cmdOptions.dbPass,
        });

        if (!opts.json && !cmdOptions.json) {
          console.log(`\nDatabase optimization ${dryRun ? 'preview' : 'completed'}`);
          console.log(`Table prefix: ${result.prefix}`);
          console.log(`Tables affected: ${result.summary.tablesAffected}`);
          console.log(`Total tasks: ${result.summary.totalTasks}`);

          if (dryRun) {
            console.log(`\nMode: DRY RUN (use --force to generate script)`);
            console.log(`\nOptimization queries:\n`);
            for (const task of result.tasks) {
              console.log(`  [${task.action}] ${task.table}`);
              console.log(`    ${task.query}`);
              console.log(`    Savings: ${task.savingsEstimate}`);
              console.log('');
            }
          } else if (result.scriptPath) {
            console.log(`\nOptimization script saved to: ${result.scriptPath}`);
            console.log('Review and run the script manually to apply changes.');
          }
        }

        formatOutput(result, opts.json || cmdOptions.json);
      } catch (err) {
        const error = {
          success: false,
          error: String(err),
          dryRun,
        };
        formatOutput(error, opts.json || cmdOptions.json);
        process.exit(1);
      }
    });
}
