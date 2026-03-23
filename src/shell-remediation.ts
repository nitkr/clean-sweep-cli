import * as path from 'path';

export interface PermissionIssueInput {
  file: string;
  suggestedMode: string;
  type: string;
}

export interface ThreatInput {
  file: string;
  signature: string;
  type: string;
}

export interface ChmodCommand {
  command: string;
  file: string;
  mode: string;
  issueType: string;
}

export interface RmCommand {
  command: string;
  file: string;
  threatType: string;
  signature: string;
}

export interface BackupCommand {
  command: string;
  source: string;
  destination: string;
}

export interface RemediationScript {
  header: string;
  backupSection: string[];
  permissionFixSection: string[];
  removalSection: string[];
  fullScript: string;
}

export function generateChmodCommands(issues: PermissionIssueInput[]): ChmodCommand[] {
  return issues.map((issue) => ({
    command: `chmod ${issue.suggestedMode} "${issue.file}"`,
    file: issue.file,
    mode: issue.suggestedMode,
    issueType: issue.type,
  }));
}

export function generateRmCommands(threats: ThreatInput[]): RmCommand[] {
  return threats.map((threat) => ({
    command: `rm -f "${threat.file}"`,
    file: threat.file,
    threatType: threat.type,
    signature: threat.signature,
  }));
}

export function generateBackupCommands(
  filePaths: string[],
  backupDir: string
): BackupCommand[] {
  const commands: BackupCommand[] = [];

  commands.push({
    command: `mkdir -p "${backupDir}"`,
    source: '',
    destination: backupDir,
  });

  for (const filePath of filePaths) {
    const relativePath = path.basename(filePath);
    const destPath = path.join(backupDir, relativePath);
    commands.push({
      command: `cp -p "${filePath}" "${destPath}"`,
      source: filePath,
      destination: destPath,
    });
  }

  return commands;
}

export function generateRemediationScript(
  permissionIssues: PermissionIssueInput[],
  threats: ThreatInput[],
  backupDir: string
): RemediationScript {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const header = [
    '#!/usr/bin/env bash',
    '#',
    '# Clean Sweep Remediation Script',
    `# Generated: ${new Date().toISOString()}`,
    '#',
    '# WARNING: Review this script carefully before executing.',
    '# Run with: bash remediation.sh',
    '#',
    'set -euo pipefail',
    '',
  ].join('\n');

  const allFiles = [
    ...permissionIssues.map((i) => i.file),
    ...threats.map((t) => t.file),
  ];
  const uniqueFiles = [...new Set(allFiles)];

  const backupCommands = generateBackupCommands(uniqueFiles, backupDir);
  const backupSection = [
    '# ============================================================',
    '# Step 1: Backup affected files',
    '# ============================================================',
    'echo "Creating backups..."',
    ...backupCommands.map((c) => c.command),
    'echo "Backup complete."',
    '',
  ];

  const chmodCommands = generateChmodCommands(permissionIssues);
  const permissionFixSection = [
    '# ============================================================',
    '# Step 2: Fix file permissions',
    '# ============================================================',
    'echo "Fixing permissions..."',
    ...chmodCommands.map((c) => c.command),
    'echo "Permission fixes applied."',
    '',
  ];

  const rmCommands = generateRmCommands(threats);
  const removalSection = [
    '# ============================================================',
    '# Step 3: Remove malware',
    '# ============================================================',
    'echo "Removing infected files..."',
    ...rmCommands.map((c) => c.command),
    'echo "Removal complete."',
    '',
  ];

  const fullScript = [
    header,
    ...backupSection,
    ...permissionFixSection,
    ...removalSection,
    'echo "Remediation complete."',
  ].join('\n');

  return {
    header,
    backupSection,
    permissionFixSection,
    removalSection,
    fullScript,
  };
}
