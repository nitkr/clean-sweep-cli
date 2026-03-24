# Clean Sweep CLI

A standalone Node.js/TypeScript CLI for securing and managing WordPress installations. No WP-CLI or PHP dependencies required.

## Features

- **Malware Scanning** - Signature-based detection with 100+ patterns
- **Core Repair** - Reinstall WordPress core files from wordpress.org
- **Plugin/Theme Management** - Reinstall official plugins and themes
- **Database Security** - Scan for malware, spam, and suspicious content
- **User Security** - Shadow account detection, inactive users, suspicious logins
- **Cron Security** - Detect malicious cron entries, monitor clean-sweep jobs
- **SSL/Environment** - Certificate checks, server validation
- **Auto-Detection** - Finds WordPress installations automatically
- **JSON Output** - Machine-readable results for all commands

## Quick Start

```bash
git clone https://github.com/nitkr/clean-sweep-cli.git
cd clean-sweep-cli
npm install && npm run build

# Scan a WordPress site
clean-sweep scan --path /var/www/html --json

# Full security audit
clean-sweep scan --path /var/www/html --check-vulnerabilities --check-integrity --find-unknown

# Check for suspicious users
clean-sweep users:check --path /var/www/html --db

# Schedule periodic scans
clean-sweep schedule --path /var/www/html --daily
```

## Global Flags

| Flag | Description |
|------|-------------|
| `--dry-run` | Preview without executing (default varies by command) |
| `--force` | Skip prompts, execute actions |
| `--json` | JSON output |
| `--path <path>` | Target WordPress directory |
| `--verbose` | Detailed output |

## Commands

| Command | Description |
|---------|-------------|
| `scan` | Scan for malware, vulnerabilities, unknown files |
| `core:repair` | Reinstall WordPress core files |
| `plugin:reinstall` | Reinstall a WordPress.org plugin |
| `theme:reinstall` | Reinstall a WordPress.org theme |
| `file:extract` | Extract ZIP to WordPress directories |
| `db:scan` | Scan database for threats |
| `users:check` | Detect shadow accounts, inactive users |
| `cron:check` | Detect malicious cron entries |
| `cron:guard` | Monitor clean-sweep cron jobs |
| `status` | WordPress health status |
| `schedule` | Setup periodic scan cron jobs |
| `permissions:check` | Audit file permissions |
| `config:validate` | Validate wp-config.php |
| `harden:check` | Security hardening checks |
| `ssl:check` | SSL certificate validation |
| `env:check` | Server environment check |

See [docs/commands.md](docs/commands.md) for detailed command documentation.

## Development

```bash
npm run build    # Build TypeScript
npm test         # Run tests
npm run type-check  # Type check without building
```

## Documentation

- [Command Reference](docs/commands.md) - Detailed command documentation
- [Development Guide](docs/development.md) - Project development info
- [Architecture](docs/architecture.md) - Design decisions

## License

MIT
