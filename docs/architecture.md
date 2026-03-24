# Architecture

## Design Principles

1. **Standalone** - No WP-CLI, PHP, or external dependencies required for runtime
2. **Safe by Default** - Destructive commands require `--force` flag
3. **JSON First** - All commands support JSON output for programmatic use
4. **Auto-Detection** - Find WordPress installations automatically
5. **Modular** - Each command is self-contained with clear interfaces

## CLI Architecture

### Entry Point

`bin/clean-sweep` → `src/index.ts` → registers all commands

### Command Registration Pattern

```typescript
export function registerCommand(
  program: Command,
  getOpts: () => CliOptions
): void {
  program
    .command('namespace:name')
    .description('Description')
    .option('--json', 'Output as JSON', false)
    .action(async (cmdOptions) => {
      const opts = getOpts();
      // Implementation
    });
}
```

### Global Options

Global options are defined once in `src/index.ts` and accessed via `getOpts()`:

```typescript
interface CliOptions {
  dryRun: boolean;
  force: boolean;
  json: boolean;
  path: string;
  verbose: boolean;
  checkVulnerabilities: boolean;
  checkIntegrity: boolean;
  findUnknown: boolean;
  report: boolean;
  htmlReport: boolean;
  logLevel: string;
}
```

## Malware Detection

### Tiered Approach

1. **High Confidence Patterns** - eval with user input, command injection, RFI, etc.
2. **Medium Confidence Patterns** - Suspicious function calls, encoding, etc.
3. **Custom Signatures** - User-defined patterns from signatures/
4. **Generic Patterns** - Fallback for common malware

### Signature Files

Located in `signatures/`:
- `php-signatures.json` - PHP malware patterns
- `js-signatures.json` - JavaScript malware patterns
- `db-signatures.json` - Database malware patterns
- `file-patterns.json` - File-based detection patterns

## File Integrity

Maintains SHA-256 hashes of WordPress core files in `src/file-integrity.ts`. Detects:
- Modified core files
- Added suspicious files
- Missing core files

## WordPress Detection

`src/wp-path-detector.ts` walks up parent directories looking for `wp-config.php`:

```typescript
detectWordPressRoot('/var/www/html/plugins/myplugin')
// Returns /var/www/html if wp-config.php found there
```

## Database Operations

### Auto-Detection

Parses `wp-config.php` to extract DB credentials:

```typescript
const creds = parseWpConfig('wp-config.php');
// { host, name, user, pass, prefix }
```

### Scanning

Uses `mysql` CLI for database queries:
- Table scanning for malware patterns
- User table analysis
- Post/meta content scanning

## Cron Management

### Markers

Clean Sweep cron jobs are marked with `# clean-sweep` comment:

```
0 2 * * * /path/to/clean-sweep scan --path /var/www/html # clean-sweep
```

### Commands

- `cron:manage` - Enable/disable clean-sweep jobs
- `cron:check` - Detect malicious cron entries system-wide
- `cron:guard` - Monitor clean-sweep jobs for tampering

## Security Checks

### Users Check

Detects shadow accounts and security issues:
- Default admin username/email
- Multiple admin accounts
- Suspicious login names
- Disposable/spam emails
- Inactive accounts (90+ days)
- Soft-deleted/spam status

### Hardening Checks

Validates:
- .htaccess security rules
- File permissions
- wp-config.php security
- Security plugin presence

## Output Directories

All output organized under `clean-sweep-cli/` namespace:

```
clean-sweep-cli/
├── logs/           # Scan logs
├── reports/        # JSON/HTML reports
├── backups/        # Core/plugin backups
├── quarantine/     # Quarantined files
└── quarantine-backup/
```

## Error Handling

All commands:
1. Validate inputs early
2. Provide clear error messages with suggestions
3. Return appropriate exit codes (0 = success, 1 = issues found)
4. Support `--json` for machine-readable errors

## Testing Strategy

- **Unit Tests** - Pure functions, mocked dependencies
- **Integration Tests** - Use `test/fixtures/` WordPress installations
- **CLI Tests** - End-to-end command execution tests

Tests are gitignored (not committed) but fixtures are tracked.

## Performance Considerations

- Batch file scanning for large directories
- Lazy loading of signature files
- Configurable timeout for API calls
- Memory-efficient streaming for large files

## Extension Points

1. **Custom Signatures** - Add to `custom-signatures.json`
2. **Whitelist Files** - `--whitelist-file` for false positive reduction
3. **Report Templates** - Custom HTML report styling
4. **Remote Signature Sources** - `update-signatures --url`
