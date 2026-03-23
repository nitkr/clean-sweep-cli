# Clean Sweep CLI

CLI tool for cleaning and managing WordPress installations.

## Installation

```bash
npm install
npm run build
```

## Global Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--dry-run` | Preview changes without applying them | `true` |
| `--force` | Skip confirmation prompts, execute actions | `false` |
| `--json` | Output results as JSON | `false` |
| `--path <path>` | Target path to operate on | `process.cwd()` |
| `--verbose` | Show detailed output | `false` |

## Commands

### scan

Scan a WordPress installation for malware, vulnerabilities, and integrity issues.

```bash
clean-sweep scan --path /var/www/html
clean-sweep scan --path /var/www/html --check-vulnerabilities --check-integrity --find-unknown
clean-sweep scan --path /var/www/html --verbose --report --log-level debug
```

**Options:**
- `--path <path>` - Directory to scan (required)
- `--verbose` - Show detailed threat information including signatures
- `--check-vulnerabilities` - Check for known WordPress vulnerabilities
- `--check-integrity` - Check WordPress core file integrity
- `--find-unknown` - Find unknown files not part of WordPress core
- `--report` - Save JSON report to file
- `--log-level <level>` - Logging verbosity: `debug`, `info`, `warn`, `error`

### core:repair

Repair WordPress core files by replacing with fresh download from wordpress.org. Preserves `wp-config.php`, `wp-content`, `.htaccess`, and `robots.txt`.

```bash
clean-sweep core:repair --path /var/www/html
clean-sweep core:repair --path /var/www/html --force
```

### plugin:reinstall

Reinstall an official WordPress.org plugin. Downloads latest stable version and replaces existing installation.

```bash
clean-sweep plugin:reinstall --path /var/www/html --plugin akismet
clean-sweep plugin:reinstall --path /var/www/html --plugin wordpress-seo --force
```

**Options:**
- `--path <path>` - WordPress installation path (required)
- `--plugin <slug>` - Plugin slug to reinstall (required, e.g., `akismet`, `wordpress-seo`)

### file:extract

Extract a ZIP file to a WordPress folder (default: `wp-content/uploads/`).

```bash
clean-sweep file:extract --path /var/www/html --zip backup.tar.gz
clean-sweep file:extract --path /var/www/html --zip upload.tar.gz --target wp-content/uploads/ --force
```

**Options:**
- `--path <path>` - WordPress installation path (required)
- `--zip <path>` - Path to ZIP file to extract (required)
- `--target <dir>` - Target directory (default: `wp-content/uploads/`)

### db:scan

Scan WordPress database tables for suspicious content (malware, spam, malicious links).

```bash
clean-sweep db:scan --path /var/www/html
clean-sweep db:scan --path /var/www/html --force
clean-sweep db:scan --path /var/www/html --db-host localhost --db-name wp_db --db-user root --db-pass secret --force
```

**Options:**
- `--path <path>` - WordPress installation path (required)
- `--db-host <host>` - Database host (optional if wp-config.php exists)
- `--db-name <name>` - Database name (optional if wp-config.php exists)
- `--db-user <user>` - Database user (optional if wp-config.php exists)
- `--db-pass <pass>` - Database password (optional if wp-config.php exists)

### cleanup

Remove Clean Sweep toolkit files (backups, temp files) from a WordPress installation. **Requires `--force` flag - never runs automatically.**

```bash
clean-sweep cleanup --path /var/www/html --force
```

### status

Show WordPress installation health status.

```bash
clean-sweep status --path /var/www/html
clean-sweep status --path /var/www/html --json
```

Displays: WordPress version, plugins count, themes count, database connection status, wp-content writability, last core update check.

## Development

```bash
npm run build    # Build the project
npm run type-check  # Type check without building
npm test         # Run tests
```
