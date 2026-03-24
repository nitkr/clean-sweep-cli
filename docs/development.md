# Development Guide

## Project Setup

```bash
# Clone and install
git clone https://github.com/nitkr/clean-sweep-cli.git
cd clean-sweep-cli
npm install

# Build
npm run build

# Run tests
npm test

# Type check without building
npm run type-check
```

## Project Structure

```
clean-sweep-cli/
├── bin/
│   └── clean-sweep          # CLI entry point script
├── src/
│   ├── index.ts             # Main entry, command registration
│   ├── commands/            # All command implementations
│   │   ├── scan.ts
│   │   ├── core-repair.ts
│   │   ├── users-check.ts
│   │   └── ...
│   ├── malware-scanner.ts   # Core scanning logic
│   ├── vulnerability-scanner.ts
│   ├── file-integrity.ts
│   ├── wp-file-detector.ts
│   ├── wp-path-detector.ts
│   └── ...
├── signatures/              # Malware signature files
│   ├── php-signatures.json
│   ├── js-signatures.json
│   ├── db-signatures.json
│   └── file-patterns.json
├── test/
│   └── fixtures/           # Test WordPress fixtures
│       ├── wp-complete/
│       └── wp-empty/
└── docs/                    # Documentation
```

## Adding a New Command

1. Create the command file in `src/commands/`:
```typescript
// src/commands/my-command.ts
import { Command } from 'commander';

interface CliOptions {
  dryRun: boolean;
  force: boolean;
  json: boolean;
  path: string;
  verbose: boolean;
}

export function registerMyCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  program
    .command('my:command')
    .description('Description of what it does')
    .option('--json', 'Output results as JSON', false)
    .action(async (cmdOptions) => {
      const opts = getOpts();
      const useJson = cmdOptions.json || opts.json;

      // Implementation
      const result = { success: true, message: 'Done' };

      if (useJson) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.log(result.message);
      }

      process.exit(0);
    });
}
```

2. Register in `src/index.ts`:
```typescript
import { registerMyCommand } from './commands/my-command';

// In the registerCommands function:
registerMyCommand(program, getOpts);
```

3. Add tests in `tests/` (gitignored, not committed)

## Key Patterns

### Boolean Flag Handling

Use `||` instead of `??` for boolean flags to properly override defaults:

```typescript
// CORRECT - user's explicit flag overrides default
const useJson = cmdOptions.json || opts.json;

// WRONG - ?? doesn't override false default
const useJson = cmdOptions.json ?? opts.json;
```

### Dry-Run Logic

For destructive commands, use this pattern:

```typescript
const shouldExecute = (cmdOptions.force || opts.force) && !(cmdOptions.dryRun || opts.dryRun);

if (!shouldExecute) {
  console.log('[DRY-RUN] Would delete file: example.txt');
  return;
}
// Actually delete the file
```

### Path Detection

Auto-detect WordPress installations:

```typescript
import { detectWordPressRoot, formatWpPathError } from './wp-path-detector';

const wpResult = detectWordPressRoot(targetPath);
if (!wpResult.found) {
  const error = { error: formatWpPathError(wpResult, 'command:name'), path: targetPath };
  console.log(JSON.stringify(error, null, 2));
  process.exit(1);
  return;
}
targetPath = wpResult.path;
```

### Process Exit Returns

Always add `return` after `process.exit()` to prevent continued execution:

```typescript
if (error) {
  formatOutput(error, useJson);
  process.exit(1);
  return;  // Prevent continued execution
}
```

## Testing

Tests use Jest and are in `tests/` (gitignored).

```bash
# Run all tests
npm test

# Run specific test file
npm test -- --testPathPatterns="users-check"

# Run specific test
npm test -- --testNamePattern="should detect"
```

### Test Fixtures

Test fixtures are in `test/fixtures/` and ARE committed:

- `wp-complete/` - Full WordPress installation for integration tests
- `wp-empty/` - Empty WordPress for edge case tests
- `wp-install/` - WordPress with malware for scanning tests

## Building Binaries

```bash
# Requires pkg package
npm run build:pkg

# Creates binaries in dist/
```

## Git Workflow

1. Create feature branch
2. Make changes
3. Run tests: `npm test`
4. Commit with clear message
5. Push and create PR

### Commit Message Format

```
type: short description

Longer explanation if needed.
```

Types: `feat`, `fix`, `enhance`, `refactor`, `docs`, `test`

## Debugging

Enable verbose logging:
```bash
clean-sweep scan --path /var/www/html --verbose --log-level debug
```

Check JSON output for structured data:
```bash
clean-sweep scan --path /var/www/html --json > output.json
```
