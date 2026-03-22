# Clean Sweep CLI

CLI tool for cleaning and managing project files.

## Installation

```bash
npm install
npm run build
```

## Usage

```bash
# Scan a directory
clean-sweep scan --path /path/to/dir

# Preview changes (default)
clean-sweep scan --path /path/to/dir --dry-run

# Force execution without confirmation
clean-sweep scan --path /path/to/dir --force

# Output as JSON
clean-sweep scan --path /path/to/dir --json
```

## Options

- `--dry-run` - Preview changes without applying them (default: true)
- `--force` - Skip confirmation prompts
- `--json` - Output results as JSON
- `--path <path>` - Target path to operate on

## Commands

- `scan` - Scan directory for files and directories

## Development

```bash
npm run build    # Build the project
npm run type-check  # Type check without building
npm test         # Run tests
```
