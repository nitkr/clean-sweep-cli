import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import { checkPermissions, PermissionIssue, PermissionsCheckResult } from './permissions-check';
import { validateConfig, ConfigValidateResult, ConfigIssue } from './config-validate';
import { checkHarden, HardenCheckResult } from './harden-check';

export interface FixAction {
  check: 'permissions' | 'config' | 'harden';
  file: string;
  issue: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  fixType: 'chmod' | 'config_edit' | 'htaccess_add';
  fixDescription: string;
  applied: boolean;
  error?: string;
}

export interface FixResult {
  path: string;
  dryRun: boolean;
  summary: {
    totalIssues: number;
    fixableIssues: number;
    applied: number;
    skipped: number;
    failed: number;
  };
  actions: FixAction[];
  permissionsResult: PermissionsCheckResult;
  configResult: ConfigValidateResult | null;
  hardenResult: HardenCheckResult | null;
}

const HTACCESS_SECURITY_BLOCK = `# BEGIN Clean Sweep Security Rules
Options -Indexes
<Files wp-config.php>
  Require all denied
</Files>
<FilesMatch "\\.php$">
  Require all denied
</FilesMatch>
<Files xmlrpc.php>
  Require all denied
</Files>
# END Clean Sweep Security Rules
`;

const UPLOADS_HTACCESS_BLOCK = `# BEGIN Clean Sweep - Block PHP execution
<FilesMatch "\\.php$">
  Deny from all
</FilesMatch>
# END Clean Sweep - Block PHP execution
`;

export function collectFixActions(
  targetPath: string,
  permissionsResult: PermissionsCheckResult,
  configResult: ConfigValidateResult | null,
  hardenResult: HardenCheckResult | null
): FixAction[] {
  const actions: FixAction[] = [];

  for (const issue of permissionsResult.issues) {
    if (issue.type === 'world_writable') {
      actions.push({
        check: 'permissions',
        file: issue.file,
        issue: issue.description,
        severity: issue.severity,
        fixType: 'chmod',
        fixDescription: `chmod ${issue.suggestedMode} "${issue.file}"`,
        applied: false,
      });
    } else if (issue.type === 'setuid_setgid') {
      actions.push({
        check: 'permissions',
        file: issue.file,
        issue: issue.description,
        severity: issue.severity,
        fixType: 'chmod',
        fixDescription: `chmod ${issue.suggestedMode} "${issue.file}"`,
        applied: false,
      });
    } else if (issue.type === 'world_readable_sensitive') {
      actions.push({
        check: 'permissions',
        file: issue.file,
        issue: issue.description,
        severity: issue.severity,
        fixType: 'chmod',
        fixDescription: `chmod ${issue.suggestedMode} "${issue.file}"`,
        applied: false,
      });
    } else if (issue.type === 'unexpected_executable') {
      actions.push({
        check: 'permissions',
        file: issue.file,
        issue: issue.description,
        severity: issue.severity,
        fixType: 'chmod',
        fixDescription: `chmod ${issue.suggestedMode} "${issue.file}"`,
        applied: false,
      });
    } else if (issue.type === 'directory_world_writable') {
      actions.push({
        check: 'permissions',
        file: issue.file,
        issue: issue.description,
        severity: issue.severity,
        fixType: 'chmod',
        fixDescription: `chmod ${issue.suggestedMode} "${issue.file}"`,
        applied: false,
      });
    }
  }

  if (configResult) {
    for (const issue of configResult.issues) {
      if (issue.type === 'debug_enabled' && issue.constant) {
        actions.push({
          check: 'config',
          file: configResult.path,
          issue: issue.message,
          severity: issue.severity,
          fixType: 'config_edit',
          fixDescription: `Set ${issue.constant} to false in wp-config.php`,
          applied: false,
        });
      } else if (issue.type === 'insecure_config' && issue.constant && !issue.constant.includes('KEY') && !issue.constant.includes('SALT')) {
        if (issue.constant === 'DISALLOW_FILE_EDIT') {
          actions.push({
            check: 'config',
            file: configResult.path,
            issue: issue.message,
            severity: issue.severity,
            fixType: 'config_edit',
            fixDescription: `Set ${issue.constant} to true in wp-config.php`,
            applied: false,
          });
        } else if (issue.constant === 'FORCE_SSL_ADMIN') {
          actions.push({
            check: 'config',
            file: configResult.path,
            issue: issue.message,
            severity: issue.severity,
            fixType: 'config_edit',
            fixDescription: `Set ${issue.constant} to true in wp-config.php`,
            applied: false,
          });
        }
      }
    }
  }

  if (hardenResult) {
    const missingRules = hardenResult.htaccessChecks.filter(c => !c.present);
    const htaccessPath = hardenResult.htaccessChecks[0]?.file;
    const htaccessExists = htaccessPath && fs.existsSync(htaccessPath);

    if (!htaccessExists || missingRules.length > 0) {
      if (htaccessPath) {
        actions.push({
          check: 'harden',
          file: htaccessPath,
          issue: 'Missing .htaccess security rules',
          severity: 'HIGH',
          fixType: 'htaccess_add',
          fixDescription: `Create/update .htaccess with security rules`,
          applied: false,
        });
      }
    }

    const uploadsHtaccess = path.join(targetPath, 'wp-content', 'uploads', '.htaccess');
    const uploadsRule = hardenResult.htaccessChecks.find(c => c.rule === 'uploads_block_php');
    if (uploadsRule && !uploadsRule.present) {
      actions.push({
        check: 'harden',
        file: uploadsHtaccess,
        issue: 'PHP execution not blocked in uploads directory',
        severity: 'HIGH',
        fixType: 'htaccess_add',
        fixDescription: `Create .htaccess in wp-content/uploads to block PHP execution`,
        applied: false,
      });
    }

    for (const issue of hardenResult.filePermissionIssues) {
      actions.push({
        check: 'harden',
        file: issue.file,
        issue: issue.issue,
        severity: issue.severity,
        fixType: 'chmod',
        fixDescription: `chmod ${issue.recommendedMode} "${issue.file}"`,
        applied: false,
      });
    }
  }

  return actions;
}

export function applyPermissionFix(action: FixAction): boolean {
  try {
    const mode = parseInt(action.fixDescription.split(' ')[1].replace(/['"]/g, ''), 8);
    fs.chmodSync(action.file, mode);
    return true;
  } catch {
    return false;
  }
}

export function applyConfigFix(action: FixAction): boolean {
  try {
    let content = fs.readFileSync(action.file, 'utf-8');

    const constant = action.fixDescription.includes('WP_DEBUG_DISPLAY')
      ? 'WP_DEBUG_DISPLAY'
      : action.fixDescription.includes('WP_DEBUG_LOG')
      ? 'WP_DEBUG_LOG'
      : action.fixDescription.includes('WP_DEBUG')
      ? 'WP_DEBUG'
      : action.fixDescription.includes('SCRIPT_DEBUG')
      ? 'SCRIPT_DEBUG'
      : action.fixDescription.includes('DISALLOW_FILE_EDIT')
      ? 'DISALLOW_FILE_EDIT'
      : action.fixDescription.includes('FORCE_SSL_ADMIN')
      ? 'FORCE_SSL_ADMIN'
      : null;

    if (!constant) return false;

    const targetValue = (constant === 'DISALLOW_FILE_EDIT' || constant === 'FORCE_SSL_ADMIN') ? 'true' : 'false';
    const pattern = new RegExp(
      `(define\\s*\\(\\s*['"]${constant}['"]\\s*,\\s*)(true|false)`,
      'i'
    );

    if (pattern.test(content)) {
      content = content.replace(pattern, `$1${targetValue}`);
      fs.writeFileSync(action.file, content, 'utf-8');
      return true;
    }

    return false;
  } catch {
    return false;
  }
}

export function applyHtaccessFix(action: FixAction): boolean {
  try {
    // Special case for uploads .htaccess - different block content
    if (action.file.endsWith('uploads/.htaccess')) {
      const dir = path.dirname(action.file);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(action.file, UPLOADS_HTACCESS_BLOCK, 'utf-8');
      return true;
    }

    const htaccessPath = action.file;
    let existingContent = '';

    if (fs.existsSync(htaccessPath)) {
      existingContent = fs.readFileSync(htaccessPath, 'utf-8');
      const beginMarker = '# BEGIN Clean Sweep Security Rules';
      const endMarker = '# END Clean Sweep Security Rules';

      const beginIdx = existingContent.indexOf(beginMarker);
      const endIdx = existingContent.indexOf(endMarker);

      if (beginIdx !== -1 && endIdx !== -1) {
        const before = existingContent.substring(0, beginIdx);
        // Include the newline after end marker if present
        const endMarkerEnd = endIdx + endMarker.length;
        const after = existingContent.substring(endMarkerEnd);
        // Normalize: remove trailing newlines from before, leading newlines from after
        existingContent = before.replace(/\n+$/, '') + '\n' + after.replace(/^\n+/, '');
      }
    }

    const finalContent = existingContent.replace(/\n+$/, '') + '\n' + HTACCESS_SECURITY_BLOCK + '\n';
    fs.writeFileSync(htaccessPath, finalContent, 'utf-8');
    return true;
  } catch {
    return false;
  }
}

export function applyActions(actions: FixAction[]): FixAction[] {
  const results: FixAction[] = [];

  for (const action of actions) {
    const copy: FixAction = { ...action };
    let success = false;

    switch (action.fixType) {
      case 'chmod':
        success = applyPermissionFix(copy);
        break;
      case 'config_edit':
        success = applyConfigFix(copy);
        break;
      case 'htaccess_add':
        success = applyHtaccessFix(copy);
        break;
    }

    copy.applied = success;
    if (!success) {
      copy.error = 'Failed to apply fix';
    }
    results.push(copy);
  }

  return results;
}

export function runFix(targetPath: string, dryRun: boolean): FixResult {
  const resolvedPath = path.resolve(targetPath);

  const permissionsResult = checkPermissions(resolvedPath);

  const wpConfigPath = path.join(resolvedPath, 'wp-config.php');
  const configResult = fs.existsSync(wpConfigPath) ? validateConfig(wpConfigPath) : null;

  const hardenResult = checkHarden(resolvedPath);

  const actions = collectFixActions(resolvedPath, permissionsResult, configResult, hardenResult);
  const fixableActions = actions.filter(a =>
    a.fixType === 'chmod' || a.fixType === 'config_edit' || a.fixType === 'htaccess_add'
  );

  let appliedActions: FixAction[];

  if (dryRun) {
    appliedActions = fixableActions.map(a => ({ ...a, applied: false }));
  } else {
    appliedActions = applyActions(fixableActions);
  }

  const applied = appliedActions.filter(a => a.applied).length;
  const failed = appliedActions.filter(a => !a.applied && a.error).length;
  const skipped = appliedActions.filter(a => !a.applied && !a.error).length;

  return {
    path: resolvedPath,
    dryRun,
    summary: {
      totalIssues: permissionsResult.issues.length +
        (configResult?.issues.length || 0) +
        (hardenResult?.recommendations.filter(r => r.status === 'fail').length || 0),
      fixableIssues: fixableActions.length,
      applied,
      skipped,
      failed,
    },
    actions: appliedActions,
    permissionsResult,
    configResult,
    hardenResult,
  };
}

export function registerFixCommand(
  program: Command,
  getOpts: () => {
    dryRun: boolean;
    force: boolean;
    json: boolean;
    path: string;
    verbose: boolean;
    logLevel: string;
  }
): void {
  program
    .command('fix')
    .description('Automatically fix common security issues (permissions, config, hardening)')
    .option('--path <path>', 'Target directory to fix')
    .option('--dry-run', 'Preview changes without applying them (default)', false)
    .option('--force', 'Actually apply fixes', false)
    .option('--json', 'Output results as JSON', false)
    .action((cmdOptions) => {
      const opts = getOpts();
      const targetPath = path.resolve(cmdOptions.path || opts.path);
      const useJson = cmdOptions.json || opts.json;
      const force = cmdOptions.force || opts.force;
      const dryRun = !force;

      if (!fs.existsSync(targetPath)) {
        const error = { error: 'Path does not exist', path: targetPath };
        if (useJson) {
          console.log(JSON.stringify(error, null, 2));
        } else {
          console.error(`Error: Path does not exist: ${targetPath}`);
        }
        process.exit(1);
      }

      if (!fs.statSync(targetPath).isDirectory()) {
        const error = { error: 'Path is not a directory', path: targetPath };
        if (useJson) {
          console.log(JSON.stringify(error, null, 2));
        } else {
          console.error(`Error: Path is not a directory: ${targetPath}`);
        }
        process.exit(1);
      }

      if (!useJson) {
        console.log(`${dryRun ? '[DRY RUN] ' : ''}Running security checks on: ${targetPath}`);
      }

      const result = runFix(targetPath, dryRun);

      if (useJson) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.log('\n--- Check Results ---');
        console.log(`Permissions issues: ${result.permissionsResult.issues.length}`);
        if (result.configResult) {
          console.log(`Config issues: ${result.configResult.issues.length}`);
        }
        if (result.hardenResult) {
          const hardenFails = result.hardenResult.recommendations.filter(r => r.status === 'fail');
          console.log(`Hardening issues: ${hardenFails.length}`);
        }

        console.log(`\n--- Fix Summary ---`);
        console.log(`Total issues found: ${result.summary.totalIssues}`);
        console.log(`Fixable issues: ${result.summary.fixableIssues}`);

        if (dryRun) {
          console.log('\n[Dry run mode - no changes applied]');
          console.log('Run with --force to apply fixes.\n');

          if (result.actions.length > 0) {
            console.log('Planned fixes:');
            for (const action of result.actions) {
              console.log(`  [${action.severity}] ${action.fixDescription}`);
            }
          } else {
            console.log('No fixable issues found.');
          }
        } else {
          console.log(`Applied: ${result.summary.applied}`);
          console.log(`Failed: ${result.summary.failed}`);

          if (result.actions.length > 0) {
            for (const action of result.actions) {
              const status = action.applied ? '[FIXED]' : '[FAILED]';
              console.log(`  ${status} [${action.severity}] ${action.fixDescription}`);
              if (action.error) {
                console.log(`    Error: ${action.error}`);
              }
            }
          }
        }
      }

      const hasFailures = result.summary.failed > 0;
      const hasRemainingIssues = result.summary.applied < result.summary.fixableIssues && !dryRun;
      process.exit(hasFailures || hasRemainingIssues ? 1 : 0);
    });
}
