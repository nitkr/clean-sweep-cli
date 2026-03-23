import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import fetch from 'node-fetch';

interface PackageDependency {
  name: string;
  version: string;
  ecosystem: 'npm' | 'composer';
}

interface DepVulnerability {
  name: string;
  version: string;
  ecosystem: string;
  cve: string;
  title: string;
  severity: string;
  description: string;
  reference: string;
}

interface DepsCheckResult {
  path: string;
  filesFound: string[];
  totalDependencies: number;
  vulnerabilities: DepVulnerability[];
  hasVulnerabilities: boolean;
  bySeverity: Record<string, number>;
}

interface ComposerJson {
  require?: Record<string, string>;
  'require-dev'?: Record<string, string>;
}

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

function normalizeSeverity(severity: string | undefined): string {
  if (!severity) return 'UNKNOWN';
  const upper = severity.toUpperCase();
  if (SEVERITY_ORDER.includes(upper)) return upper;
  return 'UNKNOWN';
}

function parseComposerVersion(version: string): string {
  let cleaned = version.replace(/^[~^>=<\s]+/, '');
  cleaned = cleaned.replace(/\s*<.*/, '');
  return cleaned || version;
}

function parseNpmVersion(version: string): string {
  let cleaned = version.replace(/^[~^>=<\s]+/, '');
  cleaned = cleaned.replace(/\s*<.*/, '');
  return cleaned || version;
}

function loadComposerJson(filePath: string): PackageDependency[] {
  const content = fs.readFileSync(filePath, 'utf-8');
  const data = JSON.parse(content) as ComposerJson;
  const deps: PackageDependency[] = [];

  const sections: Array<{ deps?: Record<string, string> }> = [
    { deps: data.require },
    { deps: data['require-dev'] },
  ];

  for (const section of sections) {
    if (!section.deps) continue;
    for (const [name, version] of Object.entries(section.deps)) {
      if (name === 'php' || name.startsWith('ext-')) continue;
      deps.push({
        name,
        version: parseComposerVersion(version),
        ecosystem: 'composer',
      });
    }
  }

  return deps;
}

function loadPackageJson(filePath: string): PackageDependency[] {
  const content = fs.readFileSync(filePath, 'utf-8');
  const data = JSON.parse(content) as PackageJson;
  const deps: PackageDependency[] = [];

  const sections: Array<{ deps?: Record<string, string> }> = [
    { deps: data.dependencies },
    { deps: data.devDependencies },
  ];

  for (const section of sections) {
    if (!section.deps) continue;
    for (const [name, version] of Object.entries(section.deps)) {
      deps.push({
        name,
        version: parseNpmVersion(version),
        ecosystem: 'npm',
      });
    }
  }

  return deps;
}

const OSV_API_URL = 'https://api.osv.dev/v1/query';

async function queryOsv(dep: PackageDependency): Promise<DepVulnerability[]> {
  const ecosystem = dep.ecosystem === 'npm' ? 'npm' : 'Packagist';

  const body: Record<string, unknown> = {
    package: {
      name: dep.name,
      ecosystem,
    },
    version: dep.version,
  };

  try {
    const response = await fetch(OSV_API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      return [];
    }

    const data = (await response.json()) as {
      vulnerabilities?: Array<{
        id: string;
        summary?: string;
        details?: string;
        severity?: Array<{ type: string; score: string }>;
        references?: Array<{ type: string; url: string }>;
      }>;
    };

    if (!data.vulnerabilities || !Array.isArray(data.vulnerabilities)) {
      return [];
    }

    return data.vulnerabilities.map((vuln) => {
      let severity = 'UNKNOWN';
      if (vuln.severity && vuln.severity.length > 0) {
        const cvssEntry = vuln.severity.find((s) => s.type === 'CVSS_V3' || s.type === 'CVSS_V2');
        if (cvssEntry) {
          const scoreStr = cvssEntry.score;
          const scoreMatch = scoreStr.match(/(\d+\.?\d*)/);
          if (scoreMatch) {
            const score = parseFloat(scoreMatch[1]);
            if (score >= 9.0) severity = 'CRITICAL';
            else if (score >= 7.0) severity = 'HIGH';
            else if (score >= 4.0) severity = 'MEDIUM';
            else severity = 'LOW';
          }
        }
      }

      const url = vuln.references?.find((r) => r.url)?.url || '';

      return {
        name: dep.name,
        version: dep.version,
        ecosystem: dep.ecosystem,
        cve: vuln.id,
        title: vuln.summary || 'Unknown vulnerability',
        severity,
        description: vuln.details || '',
        reference: url,
      };
    });
  } catch {
    return [];
  }
}

export async function checkDeps(
  targetPath: string
): Promise<DepsCheckResult> {
  const filesFound: string[] = [];
  const dependencies: PackageDependency[] = [];

  const composerPath = path.join(targetPath, 'composer.json');
  const packagePath = path.join(targetPath, 'package.json');

  if (fs.existsSync(composerPath)) {
    filesFound.push('composer.json');
    try {
      dependencies.push(...loadComposerJson(composerPath));
    } catch {
      // ignore parse errors
    }
  }

  if (fs.existsSync(packagePath)) {
    filesFound.push('package.json');
    try {
      dependencies.push(...loadPackageJson(packagePath));
    } catch {
      // ignore parse errors
    }
  }

  const allVulns: DepVulnerability[] = [];

  for (const dep of dependencies) {
    const vulns = await queryOsv(dep);
    allVulns.push(...vulns);
  }

  const bySeverity: Record<string, number> = {};
  for (const vuln of allVulns) {
    bySeverity[vuln.severity] = (bySeverity[vuln.severity] || 0) + 1;
  }

  return {
    path: targetPath,
    filesFound,
    totalDependencies: dependencies.length,
    vulnerabilities: allVulns,
    hasVulnerabilities: allVulns.length > 0,
    bySeverity,
  };
}

export function registerDepsCheckCommand(
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
    .command('deps:check')
    .description('Check project dependencies for known vulnerabilities')
    .option('--path <path>', 'Target project directory')
    .option('--json', 'Output results as JSON', false)
    .option('--severity <level>', 'Filter by severity (critical, high, medium, low)')
    .action(async (cmdOptions) => {
      const opts = getOpts();
      const targetPath = path.resolve(cmdOptions.path || opts.path);
      const useJson = cmdOptions.json || opts.json;
      const severityFilter = cmdOptions.severity
        ? (cmdOptions.severity as string).toUpperCase()
        : undefined;

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
        console.log(`Checking dependencies in: ${targetPath}`);
      }

      const result = await checkDeps(targetPath);

      if (result.filesFound.length === 0) {
        const error = { error: 'No composer.json or package.json found', path: targetPath };
        if (useJson) {
          console.log(JSON.stringify(error, null, 2));
        } else {
          console.error(`No composer.json or package.json found in ${targetPath}`);
        }
        process.exit(1);
      }

      let filteredVulns = result.vulnerabilities;
      if (severityFilter) {
        filteredVulns = result.vulnerabilities.filter(
          (v) => v.severity === severityFilter
        );
      }

      const filteredBySeverity: Record<string, number> = {};
      for (const vuln of filteredVulns) {
        filteredBySeverity[vuln.severity] =
          (filteredBySeverity[vuln.severity] || 0) + 1;
      }

      const output: DepsCheckResult = {
        ...result,
        vulnerabilities: filteredVulns,
        hasVulnerabilities: filteredVulns.length > 0,
        bySeverity: filteredBySeverity,
      };

      if (useJson) {
        console.log(JSON.stringify(output, null, 2));
      } else {
        console.log(`\nDependency files found: ${result.filesFound.join(', ')}`);
        console.log(`Total dependencies: ${result.totalDependencies}`);

        if (filteredVulns.length === 0) {
          if (severityFilter) {
            console.log(`\nNo ${severityFilter.toLowerCase()} severity vulnerabilities found.`);
          } else {
            console.log('\nNo known vulnerabilities found.');
          }
        } else {
          if (severityFilter) {
            console.log(
              `\nFound ${filteredVulns.length} ${severityFilter.toLowerCase()} severity vulnerability(ies):`
            );
          } else {
            console.log(`\nFound ${filteredVulns.length} vulnerability(ies):`);
          }

          for (const vuln of filteredVulns) {
            console.log(
              `  [${vuln.severity}] ${vuln.name}@${vuln.version} (${vuln.ecosystem}) - ${vuln.title}`
            );
            console.log(`    CVE: ${vuln.cve}`);
            if (vuln.reference) {
              console.log(`    Ref: ${vuln.reference}`);
            }
          }

          console.log('\nSeverity breakdown:');
          for (const sev of SEVERITY_ORDER) {
            const count = filteredBySeverity[sev] || 0;
            if (count > 0) {
              console.log(`  ${sev}: ${count}`);
            }
          }
        }
      }

      process.exit(filteredVulns.length > 0 ? 1 : 0);
    });
}
