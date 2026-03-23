import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import fg from 'fast-glob';

export interface HtaccessCheck {
  file: string;
  rule: string;
  present: boolean;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  recommendation: string;
}

export interface FilePermissionCheck {
  file: string;
  issue: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  currentMode: string;
  recommendedMode: string;
}

export interface SecurityPluginCheck {
  name: string;
  found: boolean;
  path?: string;
  category: 'firewall' | 'scanner' | 'hardening' | 'login_protection';
}

export interface HardeningRecommendation {
  category: string;
  recommendation: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'pass' | 'fail' | 'warning';
  details?: string;
}

export interface HardenCheckResult {
  path: string;
  isWordPress: boolean;
  htaccessChecks: HtaccessCheck[];
  filePermissionIssues: FilePermissionCheck[];
  securityPlugins: SecurityPluginCheck[];
  recommendations: HardeningRecommendation[];
  score: number;
  maxScore: number;
  bySeverity: Record<string, number>;
}

const KNOWN_SECURITY_PLUGINS = [
  { name: 'Wordfence', dir: 'wordfence', category: 'firewall' as const },
  { name: 'Sucuri Security', dir: 'sucuri-scanner', category: 'firewall' as const },
  { name: 'iThemes Security', dir: 'better-wp-security', category: 'hardening' as const },
  { name: 'All In One WP Security', dir: 'all-in-one-wp-security-and-firewall', category: 'firewall' as const },
  { name: 'Security Ninja', dir: 'security-ninja', category: 'scanner' as const },
  { name: 'WP Cerber', dir: 'wp-cerber', category: 'firewall' as const },
  { name: 'BulletProof Security', dir: 'bulletproof-security', category: 'hardening' as const },
  { name: 'Shield Security', dir: 'wp-simple-firewall', category: 'firewall' as const },
  { name: 'Login LockDown', dir: 'login-lockdown', category: 'login_protection' as const },
  { name: 'Limit Login Attempts Reloaded', dir: 'limit-login-attempts-reloaded', category: 'login_protection' as const },
];

const HTACCESS_RULES = [
  {
    id: 'disable_indexing',
    rule: 'Options -Indexes',
    description: 'Directory listing disabled',
    severity: 'HIGH' as const,
    recommendation: 'Add "Options -Indexes" to .htaccess to prevent directory browsing',
  },
  {
    id: 'protect_wpconfig',
    rule: '<Files wp-config.php>',
    description: 'wp-config.php access restricted',
    severity: 'HIGH' as const,
    recommendation: 'Add <Files wp-config.php> rule to deny access to wp-config.php',
  },
  {
    id: 'protect_htaccess',
    rule: '<Files .htaccess>',
    description: '.htaccess self-protection',
    severity: 'MEDIUM' as const,
    recommendation: 'Add <Files .htaccess> rule to deny access to .htaccess itself',
  },
  {
    id: 'block_php_uploads',
    rule: '<FilesMatch "\\.php$">',
    description: 'PHP execution blocked in uploads',
    severity: 'HIGH' as const,
    recommendation: 'Block PHP execution in wp-content/uploads directory',
  },
  {
    id: 'disable_server_signature',
    rule: 'ServerSignature Off',
    description: 'Server signature hidden',
    severity: 'LOW' as const,
    recommendation: 'Add "ServerSignature Off" to hide server version information',
  },
  {
    id: 'protect_readme',
    rule: '<Files readme.html>',
    description: 'readme.html access restricted',
    severity: 'LOW' as const,
    recommendation: 'Block access to readme.html to hide WordPress version',
  },
  {
    id: 'block_xmlrpc',
    rule: '<Files xmlrpc.php>',
    description: 'xmlrpc.php access restricted',
    severity: 'HIGH' as const,
    recommendation: 'Block access to xmlrpc.php to prevent brute-force attacks',
  },
  {
    id: 'protect_includes',
    rule: '<Files wp-includes>',
    description: 'wp-includes access restricted',
    severity: 'MEDIUM' as const,
    recommendation: 'Add rewrite rules to block direct access to wp-includes',
  },
  {
    id: 'protect_admin_area',
    rule: 'RewriteCond %{REQUEST_URI} ^/wp-admin',
    description: 'wp-admin access restricted',
    severity: 'MEDIUM' as const,
    recommendation: 'Restrict wp-admin access by IP address',
  },
];

const WP_SENSITIVE_FILES = [
  { file: 'wp-config.php', mode: 0o400, desc: 'wp-config.php should be read-only' },
  { file: '.htaccess', mode: 0o444, desc: '.htaccess should be read-only' },
];

function modeToString(mode: number): string {
  return '0' + (mode & 0o777).toString(8);
}

export function isWordPressSite(targetPath: string): boolean {
  const wpIndicators = [
    'wp-config.php',
    'wp-config-sample.php',
    path.join('wp-includes', 'version.php'),
    path.join('wp-content', 'themes'),
    path.join('wp-content', 'plugins'),
  ];

  return wpIndicators.some((indicator) => fs.existsSync(path.join(targetPath, indicator)));
}

export function checkHtaccess(targetPath: string): HtaccessCheck[] {
  const results: HtaccessCheck[] = [];
  const htaccessPath = path.join(targetPath, '.htaccess');

  let htaccessContent = '';
  if (fs.existsSync(htaccessPath)) {
    try {
      htaccessContent = fs.readFileSync(htaccessPath, 'utf-8');
    } catch {
      // unreadable
    }
  }

  for (const rule of HTACCESS_RULES) {
    const present = htaccessContent.includes(rule.rule);
    results.push({
      file: htaccessPath,
      rule: rule.id,
      present,
      severity: rule.severity,
      description: rule.description,
      recommendation: rule.recommendation,
    });
  }

  // Check uploads directory .htaccess
  const uploadsHtaccess = path.join(targetPath, 'wp-content', 'uploads', '.htaccess');
  if (fs.existsSync(uploadsHtaccess)) {
    try {
      const uploadsContent = fs.readFileSync(uploadsHtaccess, 'utf-8');
      const blocksPhp = uploadsContent.includes('php') || uploadsContent.includes('.php');
      results.push({
        file: uploadsHtaccess,
        rule: 'uploads_block_php',
        present: blocksPhp,
        severity: 'HIGH',
        description: 'PHP execution blocked in uploads directory',
        recommendation: 'Add .htaccess in wp-content/uploads to deny PHP execution',
      });
    } catch {
      // unreadable
    }
  } else {
    results.push({
      file: uploadsHtaccess,
      rule: 'uploads_block_php',
      present: false,
      severity: 'HIGH',
      description: 'PHP execution blocked in uploads directory',
      recommendation: 'Add .htaccess in wp-content/uploads to deny PHP execution',
    });
  }

  return results;
}

export function checkFilePermissions(targetPath: string): FilePermissionCheck[] {
  const issues: FilePermissionCheck[] = [];

  for (const sensitive of WP_SENSITIVE_FILES) {
    const filePath = path.join(targetPath, sensitive.file);
    if (!fs.existsSync(filePath)) continue;

    try {
      const stat = fs.lstatSync(filePath);
      const mode = stat.mode & 0o777;

      if ((mode & 0o002) !== 0) {
        issues.push({
          file: filePath,
          issue: `${sensitive.desc} (world-writable)`,
          severity: 'HIGH',
          currentMode: modeToString(mode),
          recommendedMode: modeToString(sensitive.mode),
        });
      } else if ((mode & 0o077) !== 0) {
        issues.push({
          file: filePath,
          issue: `${sensitive.desc} (group/other have permissions)`,
          severity: 'MEDIUM',
          currentMode: modeToString(mode),
          recommendedMode: modeToString(sensitive.mode),
        });
      }
    } catch {
      // stat failed
    }
  }

  // Check wp-content directory
  const wpContentDir = path.join(targetPath, 'wp-content');
  if (fs.existsSync(wpContentDir)) {
    try {
      const stat = fs.lstatSync(wpContentDir);
      const mode = stat.mode & 0o777;
      if ((mode & 0o002) !== 0) {
        issues.push({
          file: wpContentDir,
          issue: 'wp-content is world-writable',
          severity: 'HIGH',
          currentMode: modeToString(mode),
          recommendedMode: '0755',
        });
      }
    } catch {
      // stat failed
    }
  }

  // Check wp-config.php in subdirectory installs
  const wpConfigLocations = [
    path.join(targetPath, 'wp-config.php'),
    path.join(path.dirname(targetPath), 'wp-config.php'),
  ];

  for (const configPath of wpConfigLocations) {
    if (!fs.existsSync(configPath)) continue;
    if (issues.some((i) => i.file === configPath)) continue;

    try {
      const stat = fs.lstatSync(configPath);
      const mode = stat.mode & 0o777;
      if ((mode & 0o004) !== 0) {
        issues.push({
          file: configPath,
          issue: 'wp-config.php is world-readable',
          severity: 'MEDIUM',
          currentMode: modeToString(mode),
          recommendedMode: '0400',
        });
      }
    } catch {
      // stat failed
    }
  }

  return issues;
}

export function checkSecurityPlugins(targetPath: string): SecurityPluginCheck[] {
  const pluginsDir = path.join(targetPath, 'wp-content', 'plugins');
  const results: SecurityPluginCheck[] = [];

  for (const plugin of KNOWN_SECURITY_PLUGINS) {
    const pluginPath = path.join(pluginsDir, plugin.dir);
    const found = fs.existsSync(pluginPath);
    results.push({
      name: plugin.name,
      found,
      path: found ? pluginPath : undefined,
      category: plugin.category,
    });
  }

  return results;
}

export function generateRecommendations(
  htaccessChecks: HtaccessCheck[],
  permissionIssues: FilePermissionCheck[],
  securityPlugins: SecurityPluginCheck[]
): HardeningRecommendation[] {
  const recommendations: HardeningRecommendation[] = [];

  // .htaccess recommendations
  const missingHtaccessRules = htaccessChecks.filter((c) => !c.present);
  const htaccessPath = htaccessChecks[0]?.file;
  if (!fs.existsSync(htaccessPath || '')) {
    recommendations.push({
      category: '.htaccess',
      recommendation: 'Create a .htaccess file with security rules',
      severity: 'HIGH',
      status: 'fail',
      details: 'No .htaccess file found in the WordPress root directory',
    });
  } else {
    for (const check of missingHtaccessRules) {
      recommendations.push({
        category: '.htaccess',
        recommendation: check.recommendation,
        severity: check.severity,
        status: 'fail',
        details: `Missing rule: ${check.description}`,
      });
    }
  }

  const presentHtaccessRules = htaccessChecks.filter((c) => c.present);
  if (presentHtaccessRules.length > 0) {
    recommendations.push({
      category: '.htaccess',
      recommendation: `${presentHtaccessRules.length} of ${htaccessChecks.length} security rules present`,
      severity: 'LOW',
      status: 'pass',
    });
  }

  // Permission recommendations
  for (const issue of permissionIssues) {
    recommendations.push({
      category: 'File Permissions',
      recommendation: issue.issue,
      severity: issue.severity,
      status: 'fail',
      details: `Current: ${issue.currentMode}, Recommended: ${issue.recommendedMode}`,
    });
  }

  if (permissionIssues.length === 0) {
    recommendations.push({
      category: 'File Permissions',
      recommendation: 'File permissions are properly configured',
      severity: 'LOW',
      status: 'pass',
    });
  }

  // Security plugins recommendations
  const foundPlugins = securityPlugins.filter((p) => p.found);
  const categories = new Set(foundPlugins.map((p) => p.category));

  if (foundPlugins.length === 0) {
    recommendations.push({
      category: 'Security Plugins',
      recommendation: 'Install a security plugin (e.g., Wordfence, Sucuri, iThemes Security)',
      severity: 'HIGH',
      status: 'fail',
      details: 'No known security plugins detected',
    });
  } else {
    if (!categories.has('firewall')) {
      recommendations.push({
        category: 'Security Plugins',
        recommendation: 'Consider adding a firewall/security plugin',
        severity: 'MEDIUM',
        status: 'warning',
        details: 'No firewall plugin detected',
      });
    }
    if (!categories.has('login_protection')) {
      recommendations.push({
        category: 'Security Plugins',
        recommendation: 'Consider adding a login protection plugin',
        severity: 'MEDIUM',
        status: 'warning',
        details: 'No login protection plugin detected',
      });
    }
    recommendations.push({
      category: 'Security Plugins',
      recommendation: `${foundPlugins.length} security plugin(s) detected`,
      severity: 'LOW',
      status: 'pass',
      details: foundPlugins.map((p) => p.name).join(', '),
    });
  }

  return recommendations;
}

export function calculateScore(recommendations: HardeningRecommendation[]): { score: number; maxScore: number } {
  let score = 0;
  let maxScore = 0;

  const severityWeight: Record<string, number> = { HIGH: 3, MEDIUM: 2, LOW: 1 };

  for (const rec of recommendations) {
    const weight = severityWeight[rec.severity] || 1;
    maxScore += weight;
    if (rec.status === 'pass') {
      score += weight;
    } else if (rec.status === 'warning') {
      score += Math.floor(weight / 2);
    }
  }

  return { score, maxScore };
}

export function checkHarden(targetPath: string): HardenCheckResult {
  const isWordPress = isWordPressSite(targetPath);
  const htaccessChecks = checkHtaccess(targetPath);
  const filePermissionIssues = checkFilePermissions(targetPath);
  const securityPlugins = checkSecurityPlugins(targetPath);
  const recommendations = generateRecommendations(htaccessChecks, filePermissionIssues, securityPlugins);
  const { score, maxScore } = calculateScore(recommendations);

  const bySeverity: Record<string, number> = {};
  for (const rec of recommendations) {
    if (rec.status !== 'pass') {
      bySeverity[rec.severity] = (bySeverity[rec.severity] || 0) + 1;
    }
  }

  return {
    path: targetPath,
    isWordPress,
    htaccessChecks,
    filePermissionIssues,
    securityPlugins,
    recommendations,
    score,
    maxScore,
    bySeverity,
  };
}

export function registerHardenCheckCommand(
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
    .command('harden:check')
    .description('Check WordPress security hardening configuration')
    .option('--path <path>', 'Target WordPress directory')
    .option('--json', 'Output results as JSON', false)
    .action((cmdOptions) => {
      const opts = getOpts();
      const targetPath = path.resolve(cmdOptions.path || opts.path);
      const useJson = cmdOptions.json || opts.json;

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
        console.log(`Checking WordPress security hardening in: ${targetPath}`);
      }

      const result = checkHarden(targetPath);

      if (!result.isWordPress && !useJson) {
        console.warn('Warning: Directory does not appear to be a WordPress installation');
      }

      if (useJson) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        // .htaccess section
        console.log('\n--- .htaccess Security Rules ---');
        for (const check of result.htaccessChecks) {
          const status = check.present ? '[OK]' : '[MISSING]';
          console.log(`  ${status} ${check.description}`);
          if (!check.present) {
            console.log(`    Recommendation: ${check.recommendation}`);
          }
        }

        // File permissions section
        console.log('\n--- File Permissions ---');
        if (result.filePermissionIssues.length === 0) {
          console.log('  No permission issues found');
        } else {
          for (const issue of result.filePermissionIssues) {
            console.log(`  [${issue.severity}] ${issue.issue}`);
            console.log(`    File: ${issue.file}`);
            console.log(`    Mode: ${issue.currentMode} -> ${issue.recommendedMode}`);
          }
        }

        // Security plugins section
        console.log('\n--- Security Plugins ---');
        const foundPlugins = result.securityPlugins.filter((p) => p.found);
        const missingPlugins = result.securityPlugins.filter((p) => !p.found);
        if (foundPlugins.length > 0) {
          console.log('  Detected:');
          for (const plugin of foundPlugins) {
            console.log(`    [OK] ${plugin.name} (${plugin.category})`);
          }
        } else {
          console.log('  No security plugins detected');
        }
        if (missingPlugins.length > 0) {
          console.log('  Not installed:');
          for (const plugin of missingPlugins.slice(0, 5)) {
            console.log(`    [  ] ${plugin.name} (${plugin.category})`);
          }
        }

        // Recommendations summary
        console.log('\n--- Recommendations ---');
        const failed = result.recommendations.filter((r) => r.status === 'fail');
        const warnings = result.recommendations.filter((r) => r.status === 'warning');
        const passed = result.recommendations.filter((r) => r.status === 'pass');

        for (const rec of failed) {
          console.log(`  [FAIL] [${rec.severity}] ${rec.recommendation}`);
        }
        for (const rec of warnings) {
          console.log(`  [WARN] [${rec.severity}] ${rec.recommendation}`);
        }
        for (const rec of passed) {
          console.log(`  [PASS] ${rec.recommendation}`);
        }

        // Score
        console.log(`\nHardening Score: ${result.score}/${result.maxScore}`);

        if (result.bySeverity['HIGH'] > 0) {
          console.log(`\nWARNING: ${result.bySeverity['HIGH']} high-severity issue(s) found`);
        }
      }

      const hasHighSeverity = (result.bySeverity['HIGH'] || 0) > 0;
      process.exit(hasHighSeverity ? 1 : 0);
    });
}
