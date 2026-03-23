import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';

export interface LicenseInfo {
  name: string;
  type: 'plugin' | 'theme';
  slug: string;
  license: string;
  gplCompatible: boolean;
  version?: string;
  description?: string;
  author?: string;
}

export interface LicenseIssue {
  item: LicenseInfo;
  type: 'non_gpl' | 'unknown_license' | 'missing_license';
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
}

export interface LicensesCheckResult {
  path: string;
  pluginsChecked: number;
  themesChecked: number;
  totalItems: number;
  gplCompatible: number;
  gplIncompatible: number;
  licenses: LicenseInfo[];
  issues: LicenseIssue[];
  hasIssues: boolean;
  bySeverity: Record<string, number>;
  byLicense: Record<string, number>;
}

const GPL_COMPATIBLE_LICENSES = [
  'gpl-2.0-or-later',
  'gpl-2.0+',
  'gpl v2 or later',
  'gpl-2.0',
  'gpl-3.0-or-later',
  'gpl-3.0+',
  'gpl v3 or later',
  'gpl-3.0',
  'gpl2',
  'gpl3',
  'gpl',
  'gplv2',
  'gplv3',
  'mit',
  'bsd-2-clause',
  'bsd-3-clause',
  'bsd',
  'apache-2.0',
  'apache 2.0',
  'isc',
  'zlib',
];

const NON_GPL_INDICATORS = [
  'proprietary',
  'commercial',
  'closed source',
  'copyrighted',
  'all rights reserved',
  'no license',
];

function normalizeLicense(license: string): string {
  return license.trim().toLowerCase();
}

export function isGplCompatible(license: string): boolean {
  if (!license) return false;
  const normalized = normalizeLicense(license);

  if (NON_GPL_INDICATORS.some((indicator) => normalized.includes(indicator))) {
    return false;
  }

  return GPL_COMPATIBLE_LICENSES.some(
    (gplLicense) =>
      normalized === gplLicense || normalized.startsWith(gplLicense)
  );
}

function parsePluginHeader(
  content: string,
  slug: string,
  dirPath: string
): LicenseInfo | null {
  const headerBlockRegex = /\/\*\*?([\s\S]*?)\*\//;
  const match = content.match(headerBlockRegex);
  if (!match) return null;

  const header = match[1];

  const pluginNameMatch = header.match(/\*\s*Plugin Name:\s*(.+)/i);
  if (!pluginNameMatch) return null;

  const name = pluginNameMatch[1].trim();
  const getHeaderField = (field: string): string | undefined => {
    const fieldMatch = header.match(
      new RegExp(`\\*\\s*${field}:\\s*(.+)`, 'i')
    );
    return fieldMatch ? fieldMatch[1].trim() : undefined;
  };

  const license = getHeaderField('License') || '';
  const version = getHeaderField('Version');
  const description = getHeaderField('Description');
  const author = getHeaderField('Author');

  return {
    name,
    type: 'plugin',
    slug,
    license: license || 'Not specified',
    gplCompatible: isGplCompatible(license),
    version,
    description,
    author,
  };
}

function parseThemeHeader(
  content: string,
  slug: string,
  dirPath: string
): LicenseInfo | null {
  const headerBlockRegex = /\/\*\*?([\s\S]*?)\*\//;
  const match = content.match(headerBlockRegex);
  if (!match) return null;

  const header = match[1];

  const themeNameMatch = header.match(/(?:\*\s*)?Theme Name:\s*(.+)/i);
  if (!themeNameMatch) return null;

  const name = themeNameMatch[1].trim();
  const getHeaderField = (field: string): string | undefined => {
    const fieldMatch = header.match(
      new RegExp(`(?:\\*\\s*)?${field}:\\s*(.+)`, 'i')
    );
    return fieldMatch ? fieldMatch[1].trim() : undefined;
  };

  const license = getHeaderField('License') || '';
  const version = getHeaderField('Version');
  const description = getHeaderField('Description');
  const author = getHeaderField('Author');

  return {
    name,
    type: 'theme',
    slug,
    license: license || 'Not specified',
    gplCompatible: isGplCompatible(license),
    version,
    description,
    author,
  };
}

function scanPlugins(wpDir: string): LicenseInfo[] {
  const pluginsDir = path.join(wpDir, 'wp-content', 'plugins');
  if (!fs.existsSync(pluginsDir) || !fs.statSync(pluginsDir).isDirectory()) {
    return [];
  }

  const licenses: LicenseInfo[] = [];
  const entries = fs.readdirSync(pluginsDir, { withFileTypes: true });

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const pluginDir = path.join(pluginsDir, entry.name);

    const mainFiles = [
      entry.name + '.php',
      'index.php',
      'plugin.php',
    ];

    for (const mainFile of mainFiles) {
      const filePath = path.join(pluginDir, mainFile);
      if (fs.existsSync(filePath)) {
        try {
          const content = fs.readFileSync(filePath, 'utf-8');
          const info = parsePluginHeader(content, entry.name, pluginDir);
          if (info) {
            licenses.push(info);
            break;
          }
        } catch {
          // skip unreadable files
        }
      }
    }
  }

  return licenses;
}

function scanThemes(wpDir: string): LicenseInfo[] {
  const themesDir = path.join(wpDir, 'wp-content', 'themes');
  if (!fs.existsSync(themesDir) || !fs.statSync(themesDir).isDirectory()) {
    return [];
  }

  const licenses: LicenseInfo[] = [];
  const entries = fs.readdirSync(themesDir, { withFileTypes: true });

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const themeDir = path.join(themesDir, entry.name);
    const styleCss = path.join(themeDir, 'style.css');

    if (fs.existsSync(styleCss)) {
      try {
        const content = fs.readFileSync(styleCss, 'utf-8');
        const info = parseThemeHeader(content, entry.name, themeDir);
        if (info) {
          licenses.push(info);
        }
      } catch {
        // skip unreadable files
      }
    }
  }

  return licenses;
}

function detectIssues(licenses: LicenseInfo[]): LicenseIssue[] {
  const issues: LicenseIssue[] = [];

  for (const info of licenses) {
    if (!info.license || info.license === 'Not specified') {
      issues.push({
        item: info,
        type: 'missing_license',
        severity: 'MEDIUM',
        description: `${info.type === 'plugin' ? 'Plugin' : 'Theme'} "${info.name}" has no license specified`,
      });
    } else if (!info.gplCompatible) {
      issues.push({
        item: info,
        type: 'non_gpl',
        severity: 'HIGH',
        description: `${info.type === 'plugin' ? 'Plugin' : 'Theme'} "${info.name}" has non-GPL-compatible license: ${info.license}`,
      });
    }
  }

  return issues;
}

export function checkLicenses(targetPath: string): LicensesCheckResult {
  const pluginLicenses = scanPlugins(targetPath);
  const themeLicenses = scanThemes(targetPath);
  const allLicenses = [...pluginLicenses, ...themeLicenses];

  const issues = detectIssues(allLicenses);

  const gplCompatible = allLicenses.filter((l) => l.gplCompatible).length;
  const gplIncompatible = allLicenses.filter(
    (l) => !l.gplCompatible && l.license !== 'Not specified'
  ).length;

  const bySeverity: Record<string, number> = {};
  for (const issue of issues) {
    bySeverity[issue.severity] = (bySeverity[issue.severity] || 0) + 1;
  }

  const byLicense: Record<string, number> = {};
  for (const info of allLicenses) {
    const key = info.license || 'Not specified';
    byLicense[key] = (byLicense[key] || 0) + 1;
  }

  return {
    path: targetPath,
    pluginsChecked: pluginLicenses.length,
    themesChecked: themeLicenses.length,
    totalItems: allLicenses.length,
    gplCompatible,
    gplIncompatible,
    licenses: allLicenses,
    issues,
    hasIssues: issues.length > 0,
    bySeverity,
    byLicense,
  };
}

export function registerLicensesCheckCommand(
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
    .command('licenses:check')
    .description('Check plugin and theme licenses for GPL compatibility')
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
        console.log(`Checking licenses in: ${targetPath}`);
      }

      const result = checkLicenses(targetPath);

      if (useJson) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.log(`\nPlugins checked: ${result.pluginsChecked}`);
        console.log(`Themes checked: ${result.themesChecked}`);
        console.log(`Total items: ${result.totalItems}`);

        if (result.totalItems === 0) {
          console.log('\nNo plugins or themes found to check.');
        } else {
          console.log(`GPL-compatible: ${result.gplCompatible}`);
          console.log(`Non-GPL-compatible: ${result.gplIncompatible}`);

          console.log('\n--- Licenses Found ---');
          for (const info of result.licenses) {
            const compatStr = info.gplCompatible ? 'GPL-compatible' : 'NOT GPL-compatible';
            const versionStr = info.version ? ` v${info.version}` : '';
            console.log(
              `  ${info.type === 'plugin' ? '[Plugin]' : '[Theme] '} ${info.name}${versionStr} - ${info.license} (${compatStr})`
            );
          }

          if (result.issues.length === 0) {
            console.log('\nNo license issues found. All items are GPL-compatible.');
          } else {
            console.log(`\n--- License Issues (${result.issues.length}) ---`);
            for (const issue of result.issues) {
              console.log(`  [${issue.severity}] ${issue.description}`);
            }

            console.log('\nSeverity breakdown:');
            for (const sev of ['HIGH', 'MEDIUM', 'LOW']) {
              const count = result.bySeverity[sev] || 0;
              if (count > 0) {
                console.log(`  ${sev}: ${count}`);
              }
            }
          }
        }
      }

      const hasHighSeverity = (result.bySeverity['HIGH'] || 0) > 0;
      process.exit(hasHighSeverity ? 1 : 0);
    });
}
