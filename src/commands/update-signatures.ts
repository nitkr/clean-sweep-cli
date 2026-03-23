import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import * as https from 'https';
import * as http from 'http';

const DEFAULT_SIGNATURE_URL = 'https://signatures.clean-sweep-cli.example.com';
const SIGNATURE_FILES = [
  'php-signatures.json',
  'js-signatures.json',
  'db-signatures.json',
  'file-patterns.json',
];

interface CliOptions {
  dryRun: boolean;
  force: boolean;
  json: boolean;
  path: string;
  verbose: boolean;
}

interface UpdateResult {
  updated: string[];
  skipped: string[];
  errors: string[];
  dryRun: boolean;
  source: string;
  timestamp: string;
}

function formatOutput(data: unknown, useJson: boolean): void {
  if (useJson) {
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(data);
  }
}

export function getSignaturesDir(): string {
  return path.resolve(__dirname, '..', '..', 'signatures');
}

export function getSignatureUrl(baseUrl?: string): string {
  return baseUrl || process.env.CLEAN_SWEEP_SIGNATURE_URL || DEFAULT_SIGNATURE_URL;
}

export function fetchRemoteFile(url: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https') ? https : http;
    const req = client.get(url, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        fetchRemoteFile(res.headers.location).then(resolve).catch(reject);
        return;
      }

      if (res.statusCode && res.statusCode >= 400) {
        reject(new Error(`HTTP ${res.statusCode}`));
        return;
      }

      let data = '';
      res.on('data', (chunk: Buffer) => {
        data += chunk.toString();
      });
      res.on('end', () => resolve(data));
      res.on('error', reject);
    });

    req.on('error', reject);
    req.setTimeout(10000, () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });
  });
}

export function validateSignatureJson(content: string): boolean {
  try {
    const parsed = JSON.parse(content);
    return typeof parsed === 'object' && parsed !== null;
  } catch {
    return false;
  }
}

export type FetchFn = (url: string) => Promise<string>;

export async function updateSignatures(
  options: { dryRun: boolean; url: string; signaturesDir: string },
  fetchFn: FetchFn = fetchRemoteFile
): Promise<UpdateResult> {
  const { dryRun, url, signaturesDir } = options;
  const result: UpdateResult = {
    updated: [],
    skipped: [],
    errors: [],
    dryRun,
    source: url,
    timestamp: new Date().toISOString(),
  };

  if (!fs.existsSync(signaturesDir)) {
    if (dryRun) {
      result.updated = SIGNATURE_FILES.map(f => path.join(signaturesDir, f));
      return result;
    }
    fs.mkdirSync(signaturesDir, { recursive: true });
  }

  const existingFiles = fs.readdirSync(signaturesDir);

  for (const file of SIGNATURE_FILES) {
    const remoteUrl = `${url}/${file}`;
    const localPath = path.join(signaturesDir, file);

    if (dryRun) {
      result.updated.push(file);
      continue;
    }

    try {
      const content = await fetchFn(remoteUrl);

      if (!validateSignatureJson(content)) {
        result.errors.push(`${file}: invalid JSON content`);
        continue;
      }

      if (existingFiles.includes(file)) {
        const existing = fs.readFileSync(localPath, 'utf-8');
        if (existing === content) {
          result.skipped.push(file);
          continue;
        }
      }

      fs.writeFileSync(localPath, content, 'utf-8');
      result.updated.push(file);
    } catch (err) {
      result.errors.push(`${file}: ${String(err)}`);
    }
  }

  return result;
}

export function registerUpdateSignaturesCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  program
    .command('update-signatures')
    .description('Update malware signature files from a remote source')
    .option('--url <url>', 'Remote signature source URL')
    .option('--dry-run', 'Preview changes without downloading', false)
    .option('--json', 'Output results as JSON', false)
    .action(async (cmdOptions) => {
      const opts = getOpts();
      const dryRun = opts.dryRun || cmdOptions.dryRun;
      const useJson = opts.json || cmdOptions.json;
      const url = getSignatureUrl(cmdOptions.url);
      const signaturesDir = getSignaturesDir();

      try {
        const result = await updateSignatures({ dryRun, url, signaturesDir });

        if (useJson) {
          formatOutput(result, true);
        } else {
          if (dryRun) {
            console.log(`[DRY RUN] Would update ${result.updated.length} signature file(s) from ${url}`);
          } else {
            if (result.updated.length > 0) {
              console.log(`Updated ${result.updated.length} signature file(s):`);
              for (const file of result.updated) {
                console.log(`  - ${file}`);
              }
            }
            if (result.skipped.length > 0) {
              console.log(`Skipped ${result.skipped.length} file(s) (already up to date):`);
              for (const file of result.skipped) {
                console.log(`  - ${file}`);
              }
            }
            if (result.errors.length > 0) {
              console.log(`Errors updating ${result.errors.length} file(s):`);
              for (const err of result.errors) {
                console.log(`  - ${err}`);
              }
            }
            if (result.updated.length === 0 && result.errors.length === 0) {
              console.log('All signature files are up to date.');
            }
          }
        }

        if (result.errors.length > 0) {
          process.exit(1);
        }
      } catch (err) {
        const error = { error: 'Update failed', message: String(err) };
        formatOutput(error, useJson);
        process.exit(1);
      }
    });
}
