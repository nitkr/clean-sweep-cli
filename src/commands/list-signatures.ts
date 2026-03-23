import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';

interface CliOptions {
  json: boolean;
}

interface SignatureEntry {
  id: string;
  name: string;
  severity: string;
  category: string;
}

const SIGNATURES_DIR = path.resolve(__dirname, '..', '..', 'signatures');

export function getSignatureFiles(signaturesDir: string = SIGNATURES_DIR): string[] {
  if (!fs.existsSync(signaturesDir)) {
    return [];
  }
  return fs.readdirSync(signaturesDir).filter(f => f.endsWith('.json'));
}

export function loadAllSignatures(signaturesDir: string = SIGNATURES_DIR): SignatureEntry[] {
  const files = getSignatureFiles(signaturesDir);
  const signatures: SignatureEntry[] = [];

  for (const file of files) {
    const filePath = path.join(signaturesDir, file);
    try {
      const raw = JSON.parse(fs.readFileSync(filePath, 'utf-8'));

      if (Array.isArray(raw.signatures)) {
        for (const sig of raw.signatures) {
          signatures.push({
            id: sig.id,
            name: sig.name,
            severity: sig.severity,
            category: sig.category || 'uncategorized',
          });
        }
      } else if (raw.signatures && typeof raw.signatures === 'object') {
        for (const [category, entries] of Object.entries(raw.signatures)) {
          if (Array.isArray(entries)) {
            for (const sig of entries) {
              signatures.push({
                id: sig.id,
                name: sig.name,
                severity: sig.severity,
                category: sig.category || category,
              });
            }
          }
        }
      }
    } catch {
      // Skip malformed signature files
    }
  }

  return signatures;
}

export function filterSignatures(
  signatures: SignatureEntry[],
  filters: { category?: string; severity?: string }
): SignatureEntry[] {
  let result = signatures;

  if (filters.category) {
    const cat = filters.category.toLowerCase();
    result = result.filter(s => s.category.toLowerCase() === cat);
  }

  if (filters.severity) {
    const sev = filters.severity.toLowerCase();
    result = result.filter(s => s.severity.toLowerCase() === sev);
  }

  return result;
}

export function formatSignaturesTable(signatures: SignatureEntry[]): string {
  if (signatures.length === 0) {
    return 'No signatures found.';
  }

  const lines: string[] = [];
  lines.push(`ID${' '.repeat(30)}NAME${' '.repeat(32)}SEVERITY${' '.repeat(6)}CATEGORY`);
  lines.push('-'.repeat(96));

  for (const sig of signatures) {
    const id = sig.id.padEnd(32);
    const name = sig.name.padEnd(34);
    const severity = sig.severity.padEnd(14);
    lines.push(`${id}${name}${severity}${sig.category}`);
  }

  lines.push('');
  lines.push(`Total: ${signatures.length} signature(s)`);

  return lines.join('\n');
}

export function registerListSignaturesCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  program
    .command('list-signatures')
    .description('List all available malware signatures')
    .option('--json', 'Output results as JSON', false)
    .option('--category <category>', 'Filter by category')
    .option('--severity <severity>', 'Filter by severity')
    .action(async (cmdOptions) => {
      const opts = getOpts();
      const useJson = opts.json || cmdOptions.json;

      const allSignatures = loadAllSignatures();

      const filtered = filterSignatures(allSignatures, {
        category: cmdOptions.category,
        severity: cmdOptions.severity,
      });

      if (useJson) {
        console.log(JSON.stringify({ signatures: filtered, total: filtered.length }, null, 2));
      } else {
        console.log(formatSignaturesTable(filtered));
      }
    });
}
