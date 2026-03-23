import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';

interface CliOptions {
  json: boolean;
}

export interface SignatureInput {
  id: string;
  name: string;
  pattern: string;
  severity: string;
  description?: string;
  category?: string;
}

export interface SignatureCreateResult {
  signature: SignatureInput;
  filePath: string;
  created: boolean;
}

const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low'];

const DEFAULT_CUSTOM_SIGNATURES_FILE = 'custom-signatures.json';

export function validateSignature(input: SignatureInput): string[] {
  const errors: string[] = [];

  if (!input.id || input.id.trim().length === 0) {
    errors.push('Signature ID is required (--id)');
  }

  if (!input.name || input.name.trim().length === 0) {
    errors.push('Signature name is required (--name)');
  }

  if (!input.pattern || input.pattern.trim().length === 0) {
    errors.push('Signature pattern is required (--pattern)');
  } else {
    try {
      new RegExp(input.pattern);
    } catch {
      errors.push(`Invalid regex pattern: ${input.pattern}`);
    }
  }

  if (!input.severity || input.severity.trim().length === 0) {
    errors.push('Severity is required (--severity)');
  } else if (!VALID_SEVERITIES.includes(input.severity.toLowerCase())) {
    errors.push(`Invalid severity "${input.severity}". Must be one of: ${VALID_SEVERITIES.join(', ')}`);
  }

  return errors;
}

export function getCustomSignaturesPath(filePath?: string): string {
  if (filePath) {
    return path.resolve(filePath);
  }
  return path.resolve(process.cwd(), DEFAULT_CUSTOM_SIGNATURES_FILE);
}

export interface CustomSignaturesFile {
  version: string;
  description: string;
  signatures: SignatureInput[];
}

export function loadCustomSignatures(filePath: string): CustomSignaturesFile {
  if (!fs.existsSync(filePath)) {
    return {
      version: '1.0.0',
      description: 'Custom malware signatures',
      signatures: [],
    };
  }

  try {
    const raw = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    if (raw && Array.isArray(raw.signatures)) {
      return raw as CustomSignaturesFile;
    }
    return {
      version: '1.0.0',
      description: 'Custom malware signatures',
      signatures: [],
    };
  } catch {
    return {
      version: '1.0.0',
      description: 'Custom malware signatures',
      signatures: [],
    };
  }
}

export function addSignatureToFile(
  input: SignatureInput,
  filePath: string
): SignatureCreateResult {
  const existing = loadCustomSignatures(filePath);

  const duplicate = existing.signatures.find(s => s.id === input.id);
  if (duplicate) {
    throw new Error(`Signature with ID "${input.id}" already exists in ${filePath}`);
  }

  const signature: SignatureInput = {
    id: input.id.trim(),
    name: input.name.trim(),
    pattern: input.pattern.trim(),
    severity: input.severity.toLowerCase().trim(),
  };

  if (input.description) {
    signature.description = input.description.trim();
  }
  if (input.category) {
    signature.category = input.category.trim();
  }

  existing.signatures.push(signature);

  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.writeFileSync(filePath, JSON.stringify(existing, null, 2), 'utf-8');

  return {
    signature,
    filePath,
    created: true,
  };
}

export function formatCreateResult(result: SignatureCreateResult): string {
  const lines: string[] = [];
  lines.push('Signature created successfully:');
  lines.push(`  ID:       ${result.signature.id}`);
  lines.push(`  Name:     ${result.signature.name}`);
  lines.push(`  Pattern:  ${result.signature.pattern}`);
  lines.push(`  Severity: ${result.signature.severity}`);

  if (result.signature.description) {
    lines.push(`  Description: ${result.signature.description}`);
  }
  if (result.signature.category) {
    lines.push(`  Category: ${result.signature.category}`);
  }

  lines.push(`  Saved to: ${result.filePath}`);

  return lines.join('\n');
}

export function registerSignatureCreateCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  program
    .command('signature:create')
    .description('Create a new custom malware signature')
    .requiredOption('--id <id>', 'Unique signature ID')
    .requiredOption('--name <name>', 'Signature name')
    .requiredOption('--pattern <pattern>', 'Regex pattern to match')
    .requiredOption('--severity <severity>', `Severity level (${VALID_SEVERITIES.join(', ')})`)
    .option('--description <description>', 'Signature description')
    .option('--category <category>', 'Signature category')
    .option('--output <path>', 'Output file path (default: custom-signatures.json)')
    .option('--json', 'Output results as JSON', false)
    .action(async (cmdOptions) => {
      const opts = getOpts();
      const useJson = opts.json || cmdOptions.json;

      const input: SignatureInput = {
        id: cmdOptions.id,
        name: cmdOptions.name,
        pattern: cmdOptions.pattern,
        severity: cmdOptions.severity,
        description: cmdOptions.description,
        category: cmdOptions.category,
      };

      const validationErrors = validateSignature(input);
      if (validationErrors.length > 0) {
        if (useJson) {
          console.log(JSON.stringify({ error: true, errors: validationErrors }, null, 2));
        } else {
          console.error('Validation errors:');
          for (const err of validationErrors) {
            console.error(`  - ${err}`);
          }
        }
        process.exit(1);
      }

      const filePath = getCustomSignaturesPath(cmdOptions.output);

      try {
        const result = addSignatureToFile(input, filePath);

        if (useJson) {
          console.log(JSON.stringify(result, null, 2));
        } else {
          console.log(formatCreateResult(result));
        }
      } catch (err) {
        const error = { error: true, message: String(err) };
        if (useJson) {
          console.log(JSON.stringify(error, null, 2));
        } else {
          console.error(`Error: ${String(err)}`);
        }
        process.exit(1);
      }
    });
}
