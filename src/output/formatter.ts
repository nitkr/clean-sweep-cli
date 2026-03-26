import { icons } from './icons';
import { severityColor, severityIcon } from './colors';
import { createVulnerabilityTable, createThreatTable, createTable, truncatePath } from './table';
import chalk from 'chalk';

export interface ScanOutputOptions {
  path: string;
  wordpress?: string;
  plugins?: number;
  threats?: unknown[];
  vulnerabilities?: unknown[];
  safe: boolean;
  useJson: boolean;
}

export function formatScanOutput(options: ScanOutputOptions): void {
  if (options.useJson) {
    return;
  }

  console.log(`\n${icons.scanning} Clean-Sweep Vulnerability Scan`);
  console.log(`  Path       : ${options.path}`);
  if (options.wordpress) {
    console.log(`  WordPress  : ${options.wordpress}`);
  }
  if (options.plugins !== undefined) {
    console.log(`  Plugins    : ${options.plugins} found`);
  }

  if (!options.safe && options.threats && options.threats.length > 0) {
    console.log(`\n${icons.error} UNSAFE – Issues found\n`);
    const table = createThreatTable() as any;
    for (const threat of options.threats as any[]) {
      const sev = (threat as any).severity || 'medium';
      table.push([
        truncatePath((threat as any).file || threat),
        (threat as any).type || 'unknown',
        `${severityIcon(sev)} ${severityColor(sev)(sev.toUpperCase())}`
      ]);
    }
    console.log(table.toString());
  } else {
    console.log(`\n${icons.safe} ${chalk.green('SAFE')} – No threats found (safe)`);
  }
}

export { icons, severityColor, severityIcon, createTable, createVulnerabilityTable, createThreatTable };
