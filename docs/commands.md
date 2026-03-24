# Command Reference

Detailed documentation for all Clean Sweep CLI commands.

## Global Flags

These flags work with all commands:

| Flag | Description | Default |
|------|-------------|---------|
| `--dry-run` | Preview changes without applying them | varies |
| `--force` | Skip confirmation prompts, execute actions | `false` |
| `--json` | Output results as JSON | `false` |
| `--path <path>` | Target path to operate on | `process.cwd()` |
| `--verbose` | Show detailed threat information | `false` |
| `--check-vulnerabilities` | Check for known WordPress vulnerabilities | `false` |
| `--check-integrity` | Check WordPress core file integrity | `false` |
| `--find-unknown` | Find unknown files not part of WordPress core | `false` |
| `--report` | Save JSON report to file | `false` |
| `--html-report` | Save HTML report to file | `false` |
| `--log-level <level>` | Logging verbosity: `debug`, `info`, `warn`, `error` | `info` |

---

## scan

Scan a WordPress installation for malware, vulnerabilities, and integrity issues.

```bash
clean-sweep scan --path /var/www/html
clean-sweep scan --path /var/www/html --check-vulnerabilities --check-integrity --find-unknown
clean-sweep scan --path /var/www/html --verbose --report --html-report --json
```

**Options:**
- `--path <path>` - Directory to scan
- `--verbose` - Show detailed threat information including signatures
- `--check-vulnerabilities` - Check for known WordPress vulnerabilities via API
- `--check-integrity` - Check WordPress core file integrity using SHA-256 hashes
- `--find-unknown` - Find unknown files not part of WordPress core
- `--report` - Save JSON report to `reports/` directory
- `--html-report` - Save HTML report to `reports/` directory
- `--whitelist-file <path>` - Path to custom whitelist JSON file
- `--log-level <level>` - Logging verbosity

---

## core:repair

Repair WordPress core files by replacing with fresh download from wordpress.org. Preserves `wp-config.php`, `wp-content`, `.htaccess`, and `robots.txt`.

```bash
clean-sweep core:repair --path /var/www/html
clean-sweep core:repair --path /var/www/html --force
clean-sweep core:repair --path /var/www/html --version 6.4.2 --force
```

**Options:**
- `--path <path>` - WordPress installation path
- `--dry-run` - Preview changes without applying them (default: true)
- `--force` - Actually perform the replacement
- `--backup` - Create backup before repair (default: true)
- `--version <version>` - Specific WordPress version to install

---

## plugin:reinstall

Reinstall an official WordPress.org plugin. Downloads latest stable version and replaces existing installation.

```bash
clean-sweep plugin:reinstall --path /var/www/html --plugin akismet
clean-sweep plugin:reinstall --path /var/www/html --plugin wordpress-seo --force
```

**Options:**
- `--path <path>` - WordPress installation path
- `--plugin <slug>` - Plugin slug to reinstall (e.g., `akismet`, `wordpress-seo`, `woocommerce`)
- `--dry-run` - Preview changes without applying them (default: true)
- `--force` - Actually perform the reinstall
- `--backup` - Create backup before reinstall (default: true)

---

## theme:reinstall

Reinstall an official WordPress.org theme. Downloads latest stable version and replaces existing theme.

```bash
clean-sweep theme:reinstall --path /var/www/html --theme twentytwentyfour
clean-sweep theme:reinstall --path /var/www/html --theme twentytwentyfour --force
```

**Options:**
- `--path <path>` - WordPress installation path
- `--theme <slug>` - Theme slug to reinstall (e.g., `twentytwentyfour`, `twentytwentythree`)
- `--dry-run` - Preview changes without applying them (default: true)
- `--force` - Actually perform the reinstall
- `--backup` - Create backup before reinstall (default: true)

---

## file:extract

Extract a ZIP file to a WordPress folder.

```bash
clean-sweep file:extract --path /var/www/html --zip backup.zip
clean-sweep file:extract --path /var/www/html --zip upload.tar.gz --target wp-content/uploads/ --force
```

**Options:**
- `--path <path>` - WordPress installation path
- `--zip <path>` - Path to ZIP file to extract (required)
- `--target <dir>` - Target directory (default: `wp-content/uploads/`)
- `--dry-run` - Preview changes without applying them (default: true)
- `--force` - Actually extract the ZIP file

---

## db:scan

Scan WordPress database tables for suspicious content (malware, spam, malicious links).

```bash
clean-sweep db:scan --path /var/www/html
clean-sweep db:scan --path /var/www/html --force
clean-sweep db:scan --path /var/www/html --db-host localhost --db-name wp_db --db-user root --db-pass secret --force
```

**Options:**
- `--path <path>` - WordPress installation path
- `--db-host <host>` - Database host (optional if wp-config.php exists)
- `--db-name <name>` - Database name (optional if wp-config.php exists)
- `--db-user <user>` - Database user (optional if wp-config.php exists)
- `--db-pass <pass>` - Database password (optional if wp-config.php exists)
- `--dry-run` - Preview SQL queries without executing (default: true)
- `--force` - Actually execute the scan

---

## db:optimize

Generate WordPress database optimization queries and scripts.

```bash
clean-sweep db:optimize --path /var/www/html
clean-sweep db:optimize --path /var/www/html --force
```

**Options:**
- `--path <path>` - WordPress installation path
- `--db-host <host>` - Database host (optional if wp-config.php exists)
- `--db-name <name>` - Database name (optional if wp-config.php exists)
- `--db-user <user>` - Database user (optional if wp-config.php exists)
- `--db-pass <pass>` - Database password (optional if wp-config.php exists)
- `--dry-run` - Preview optimization queries without executing (default: true)
- `--force` - Generate optimization script and skip dry-run

---

## cleanup

Remove Clean Sweep toolkit files (backups, temp files) from a WordPress installation. **Requires `--force` flag - never runs automatically.**

```bash
clean-sweep cleanup --path /var/www/html --force
```

**Options:**
- `--path <path>` - WordPress installation path
- `--force` - Actually remove the files (required)

---

## status

Show WordPress installation health status.

```bash
clean-sweep status --path /var/www/html
clean-sweep status --path /var/www/html --json
```

**Options:**
- `--path <path>` - WordPress installation path
- `--json` - Output results as JSON

Displays: WordPress version, plugins count, themes count, database connection status, wp-content writability, last core update check.

---

## quarantine

Quarantine infected files by moving them to a quarantine folder.

```bash
clean-sweep quarantine --path /var/www/html
clean-sweep quarantine --path /var/www/html --force
clean-sweep quarantine --path /var/www/html --json
```

**Options:**
- `--path <path>` - Directory to scan for threats
- `--dry-run` - Preview what would be quarantined without moving files (default: true)
- `--force` - Actually quarantine infected files
- `--json` - Output results as JSON
- `--log-level <level>` - Logging verbosity

---

## restore

Restore quarantined files to their original locations.

```bash
clean-sweep restore --path /var/www/html
clean-sweep restore --path /var/www/html --folder 2026-03-23T10-00-00 --force
clean-sweep restore --path /var/www/html --json
```

**Options:**
- `--path <path>` - Target path containing quarantine folder
- `--folder <name>` - Specific quarantine folder to restore from
- `--dry-run` - Preview what would be restored without moving files (default: true)
- `--force` - Actually restore the files
- `--json` - Output results as JSON
- `--log-level <level>` - Logging verbosity

---

## summary

Show a summary of scan results with risk scoring.

```bash
clean-sweep summary --path /var/www/html
clean-sweep summary --path /var/www/html --json
```

**Options:**
- `--path <path>` - Directory to scan
- `--json` - Output results as JSON

---

## compare

Compare two JSON scan results to show changes.

```bash
clean-sweep compare baseline.json current.json
clean-sweep compare baseline.json current.json --json
```

**Options:**
- `<baseline>` - Path to the baseline scan result JSON file (positional)
- `<current>` - Path to the current scan result JSON file (positional)
- `--json` - Output results as JSON

---

## history

View scan history from saved reports.

```bash
clean-sweep history
clean-sweep history --from 2026-01-01 --to 2026-03-23
clean-sweep history --json
```

**Options:**
- `--reports-dir <dir>` - Reports directory (default: `reports`)
- `--from <date>` - Filter scans from this date (ISO 8601)
- `--to <date>` - Filter scans up to this date (ISO 8601)
- `--json` - Output results as JSON

---

## list-signatures

List all available malware signatures.

```bash
clean-sweep list-signatures
clean-sweep list-signatures --category php
clean-sweep list-signatures --severity critical --json
```

**Options:**
- `--json` - Output results as JSON
- `--category <category>` - Filter by category (php, js, db, file)
- `--severity <severity>` - Filter by severity (critical, high, medium, low)

---

## update-signatures

Update malware signature files from a remote source.

```bash
clean-sweep update-signatures
clean-sweep update-signatures --url https://example.com/signatures --force
clean-sweep update-signatures --dry-run
```

**Options:**
- `--url <url>` - Remote signature source URL
- `--dry-run` - Preview changes without downloading
- `--json` - Output results as JSON

---

## signature:create

Create a new custom malware signature.

```bash
clean-sweep signature:create \
  --id "custom-001" \
  --name "My Custom Pattern" \
  --pattern "suspicious_function" \
  --severity high \
  --description "Detects custom pattern" \
  --json
```

**Options:**
- `--id <id>` - Unique signature ID (required)
- `--name <name>` - Signature name (required)
- `--pattern <pattern>` - Regex pattern to match (required)
- `--severity <severity>` - Severity level: `critical`, `high`, `medium`, `low` (required)
- `--description <description>` - Signature description
- `--category <category>` - Signature category
- `--output <path>` - Output file path (default: `custom-signatures.json`)
- `--json` - Output results as JSON

---

## permissions:check

Audit file permissions for common security issues.

```bash
clean-sweep permissions:check --path /var/www/html
clean-sweep permissions:check --path /var/www/html --json
clean-sweep permissions:check --path /var/www/html --fix
```

**Options:**
- `--path <path>` - Target directory to check
- `--json` - Output results as JSON
- `--fix` - Show suggested permission fixes

---

## config:validate

Validate WordPress wp-config.php for syntax and security issues.

```bash
clean-sweep config:validate --path /var/www/html
clean-sweep config:validate --path /var/www/html --json
clean-sweep config:validate --config-file /path/to/wp-config.php
```

**Options:**
- `--path <path>` - Path to wp-config.php or its containing directory
- `--json` - Output results as JSON
- `--config-file <file>` - Explicit path to wp-config.php

---

## harden:check

Check WordPress security hardening configuration.

```bash
clean-sweep harden:check --path /var/www/html
clean-sweep harden:check --path /var/www/html --json
```

**Options:**
- `--path <path>` - Target WordPress directory
- `--json` - Output results as JSON

Checks: .htaccess security rules, file permissions, security plugin detection, hardening recommendations with score.

---

## fix

Automatically fix common security issues (permissions, config, hardening).

```bash
clean-sweep fix --path /var/www/html
clean-sweep fix --path /var/www/html --dry-run
clean-sweep fix --path /var/www/html --force --json
```

**Options:**
- `--path <path>` - Target directory to fix
- `--dry-run` - Preview changes without applying them (default: true)
- `--force` - Actually apply fixes
- `--json` - Output results as JSON

---

## licenses:check

Check plugin and theme licenses for GPL compatibility.

```bash
clean-sweep licenses:check --path /var/www/html
clean-sweep licenses:check --path /var/www/html --json
```

**Options:**
- `--path <path>` - Target WordPress directory
- `--json` - Output results as JSON

---

## users:check

Check WordPress admin users for suspicious accounts and default settings.

```bash
clean-sweep users:check --path /var/www/html
clean-sweep users:check --path /var/www/html --json
clean-sweep users:check --path /var/www/html --db
```

**Options:**
- `--path <path>` - Target WordPress directory
- `--json` - Output results as JSON
- `--db` - Query live database for user data

**Detects:**
- Default admin username/email
- Multiple admin accounts
- Suspicious login names (root, test, backup, sysadmin, etc.)
- Weak/unrecognized roles
- Users with no roles
- Disposable emails (mailinator, tempmail, etc.)
- Spam email domains
- Inactive users (90+ days)
- Soft-deleted/spam-marked accounts

---

## env:check

Check server environment components (PHP, Node.js, server software).

```bash
clean-sweep env:check
clean-sweep env:check --json
```

**Options:**
- `--json` - Output results as JSON

---

## ssl:check

Check SSL certificate validity, expiration, and chain for a host.

```bash
clean-sweep ssl:check --host example.com
clean-sweep ssl:check --host example.com --port 443 --json
```

**Options:**
- `--host <host>` - Hostname to check SSL certificate for (required)
- `--port <port>` - Port to connect on (default: 443)
- `--json` - Output results as JSON
- `--timeout <ms>` - Connection timeout in milliseconds (default: 10000)

---

## cron:manage

Manage clean-sweep cron jobs.

```bash
# List all cron jobs
clean-sweep cron:manage list
clean-sweep cron:manage list --json

# Enable a cron job
clean-sweep cron:manage enable 0

# Disable a cron job
clean-sweep cron:manage disable 0
```

**Subcommands:**
- `list` - List all clean-sweep cron jobs
- `enable <id>` - Enable a disabled cron job
- `disable <id>` - Disable an active cron job

**Options:**
- `--json` - Output results as JSON

---

## cron:check

Check crontab for suspicious or malicious entries.

```bash
clean-sweep cron:check
clean-sweep cron:check --json
```

**Options:**
- `--json` - Output results as JSON

**Detects:**
- Base64 encoded commands
- PHP eval() patterns
- wget/curl to external URLs
- Commands in /tmp or /var/tmp directories
- chmod 777 permissions
- Shell execution functions
- SSH authorized_keys modifications
- Netcat/network tunneling tools
- Output suppression (/dev/null)

---

## cron:guard

Monitor clean-sweep cron jobs to ensure they are running properly.

```bash
clean-sweep cron:guard
clean-sweep cron:guard --json
```

**Options:**
- `--json` - Output results as JSON

**Validates:**
- Jobs are enabled (not commented out)
- Cron expression format is valid
- Command paths exist
- No suspicious modifications

---

## schedule

Generate cron job configuration for periodic malware scans.

```bash
clean-sweep schedule --path /var/www/html --daily
clean-sweep schedule --path /var/www/html --weekly
clean-sweep schedule --path /var/www/html --monthly --json
```

**Options:**
- `--path <path>` - Directory to scan
- `--daily` - Schedule daily scans (2:00 AM)
- `--weekly` - Schedule weekly scans (Sunday 3:00 AM)
- `--monthly` - Schedule monthly scans (1st at 4:00 AM)
- `--output-dir <dir>` - Directory to write scripts and logs
- `--json` - Output results as JSON

---

## scan:batch

Scan multiple directories from a list file.

```bash
clean-sweep scan:batch --list-file /path/to/directories.txt
clean-sweep scan:batch --list-file /path/to/directories.txt --json
```

**Options:**
- `--list-file <path>` - Path to a file containing directory paths (one per line)
- `--verbose` - Show detailed threat information
- `--log-level <level>` - Logging verbosity
- `--whitelist-file <path>` - Path to custom whitelist JSON file

---

## deps:check

Check project dependencies for known vulnerabilities.

```bash
clean-sweep deps:check --path /var/www/html
clean-sweep deps:check --path /var/www/html --severity critical --json
```

**Options:**
- `--path <path>` - Target project directory
- `--json` - Output results as JSON
- `--severity <level>` - Filter by severity (critical, high, medium, low)
