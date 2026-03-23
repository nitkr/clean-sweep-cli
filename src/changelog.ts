import { ScanResult, Threat } from './malware-scanner';
import * as fs from 'fs';
import * as path from 'path';

export interface ChangelogEntry {
  timestamp: string;
  summary: string;
  threatsAdded: Threat[];
  threatsRemoved: Threat[];
  filesAdded: string[];
  filesRemoved: string[];
  statusChanged: boolean;
  previousStatus: 'SAFE' | 'UNSAFE';
  currentStatus: 'SAFE' | 'UNSAFE';
}

export interface ChangelogOptions {
  title?: string;
  includeTimestamp?: boolean;
  includeFileInfo?: boolean;
  groupByType?: boolean;
}

function threatKey(threat: Threat): string {
  return `${threat.file}:${threat.type}:${threat.signature}`;
}

export function compareScanResults(
  previous: ScanResult,
  current: ScanResult
): ChangelogEntry {
  const prevThreatMap = new Map<string, Threat>();
  for (const t of previous.threats) {
    prevThreatMap.set(threatKey(t), t);
  }

  const currThreatMap = new Map<string, Threat>();
  for (const t of current.threats) {
    currThreatMap.set(threatKey(t), t);
  }

  const threatsAdded: Threat[] = [];
  for (const [key, threat] of currThreatMap) {
    if (!prevThreatMap.has(key)) {
      threatsAdded.push(threat);
    }
  }

  const threatsRemoved: Threat[] = [];
  for (const [key, threat] of prevThreatMap) {
    if (!currThreatMap.has(key)) {
      threatsRemoved.push(threat);
    }
  }

  const prevFileSet = new Set(previous.files);
  const currFileSet = new Set(current.files);

  const filesAdded: string[] = [];
  for (const f of currFileSet) {
    if (!prevFileSet.has(f)) {
      filesAdded.push(f);
    }
  }

  const filesRemoved: string[] = [];
  for (const f of prevFileSet) {
    if (!currFileSet.has(f)) {
      filesRemoved.push(f);
    }
  }

  const previousStatus: 'SAFE' | 'UNSAFE' = previous.safe ? 'SAFE' : 'UNSAFE';
  const currentStatus: 'SAFE' | 'UNSAFE' = current.safe ? 'SAFE' : 'UNSAFE';
  const statusChanged = previousStatus !== currentStatus;

  const summaryParts: string[] = [];
  if (statusChanged) {
    summaryParts.push(`Status changed from ${previousStatus} to ${currentStatus}`);
  }
  if (threatsAdded.length > 0) {
    summaryParts.push(`${threatsAdded.length} new threat(s) detected`);
  }
  if (threatsRemoved.length > 0) {
    summaryParts.push(`${threatsRemoved.length} threat(s) resolved`);
  }
  if (filesAdded.length > 0) {
    summaryParts.push(`${filesAdded.length} file(s) added`);
  }
  if (filesRemoved.length > 0) {
    summaryParts.push(`${filesRemoved.length} file(s) removed`);
  }
  if (summaryParts.length === 0) {
    summaryParts.push('No changes detected');
  }

  return {
    timestamp: new Date().toISOString(),
    summary: summaryParts.join('; '),
    threatsAdded,
    threatsRemoved,
    filesAdded,
    filesRemoved,
    statusChanged,
    previousStatus,
    currentStatus,
  };
}

function groupThreatsByType(threats: Threat[]): Map<string, Threat[]> {
  const groups = new Map<string, Threat[]>();
  for (const t of threats) {
    const existing = groups.get(t.type) || [];
    existing.push(t);
    groups.set(t.type, existing);
  }
  return groups;
}

export function generateChangelog(
  entry: ChangelogEntry,
  options: ChangelogOptions = {}
): string {
  const {
    title = 'Clean Sweep Changelog',
    includeTimestamp = true,
    includeFileInfo = true,
    groupByType = false,
  } = options;

  const lines: string[] = [];

  lines.push(`# ${title}`);
  lines.push('');

  if (includeTimestamp) {
    lines.push(`**Generated:** ${entry.timestamp}`);
    lines.push('');
  }

  lines.push('## Summary');
  lines.push('');
  lines.push(entry.summary);
  lines.push('');

  lines.push('## Status');
  lines.push('');
  if (entry.statusChanged) {
    lines.push(`- **Previous:** ${entry.previousStatus}`);
    lines.push(`- **Current:** ${entry.currentStatus}`);
  } else {
    lines.push(`- **Status:** ${entry.currentStatus} (unchanged)`);
  }
  lines.push('');

  if (entry.threatsAdded.length > 0) {
    lines.push('## New Threats');
    lines.push('');
    if (groupByType) {
      const groups = groupThreatsByType(entry.threatsAdded);
      for (const [type, threats] of groups) {
        lines.push(`### ${type}`);
        lines.push('');
        for (const t of threats) {
          const lineInfo = t.line !== null ? ` (line ${t.line})` : '';
          lines.push(`- \`${t.file}\`${lineInfo}`);
        }
        lines.push('');
      }
    } else {
      for (const t of entry.threatsAdded) {
        const lineInfo = t.line !== null ? `:${t.line}` : '';
        lines.push(`- \`${t.file}${lineInfo}\` [${t.type}]`);
      }
      lines.push('');
    }
  }

  if (entry.threatsRemoved.length > 0) {
    lines.push('## Resolved Threats');
    lines.push('');
    if (groupByType) {
      const groups = groupThreatsByType(entry.threatsRemoved);
      for (const [type, threats] of groups) {
        lines.push(`### ${type}`);
        lines.push('');
        for (const t of threats) {
          const lineInfo = t.line !== null ? ` (line ${t.line})` : '';
          lines.push(`- \`${t.file}\`${lineInfo}`);
        }
        lines.push('');
      }
    } else {
      for (const t of entry.threatsRemoved) {
        const lineInfo = t.line !== null ? `:${t.line}` : '';
        lines.push(`- \`${t.file}${lineInfo}\` [${t.type}]`);
      }
      lines.push('');
    }
  }

  if (includeFileInfo) {
    if (entry.filesAdded.length > 0) {
      lines.push('## Files Added');
      lines.push('');
      for (const f of entry.filesAdded) {
        lines.push(`- \`${f}\``);
      }
      lines.push('');
    }

    if (entry.filesRemoved.length > 0) {
      lines.push('## Files Removed');
      lines.push('');
      for (const f of entry.filesRemoved) {
        lines.push(`- \`${f}\``);
      }
      lines.push('');
    }
  }

  return lines.join('\n');
}

export function generateChangelogFromScan(
  scanResult: ScanResult,
  options: ChangelogOptions = {}
): string {
  const {
    title = 'Clean Sweep Scan Report',
    includeTimestamp = true,
  } = options;

  const lines: string[] = [];

  lines.push(`# ${title}`);
  lines.push('');

  if (includeTimestamp) {
    lines.push(`**Generated:** ${new Date().toISOString()}`);
    lines.push('');
  }

  lines.push('## Overview');
  lines.push('');
  lines.push(`- **Scan Path:** \`${scanResult.path}\``);
  lines.push(`- **Total Files:** ${scanResult.totalFiles}`);
  lines.push(`- **Total Directories:** ${scanResult.totalDirectories}`);
  lines.push(`- **Status:** ${scanResult.safe ? 'SAFE' : 'UNSAFE'}`);
  lines.push(`- **Threats Found:** ${scanResult.threats.length}`);
  if (scanResult.whitelisted > 0) {
    lines.push(`- **Whitelisted:** ${scanResult.whitelisted}`);
  }
  lines.push('');

  if (scanResult.threats.length > 0) {
    lines.push('## Threats');
    lines.push('');

    const groups = groupThreatsByType(scanResult.threats);
    for (const [type, threats] of groups) {
      lines.push(`### ${type} (${threats.length})`);
      lines.push('');
      for (const t of threats) {
        const lineInfo = t.line !== null ? `:${t.line}` : '';
        lines.push(`- \`${t.file}${lineInfo}\``);
      }
      lines.push('');
    }
  }

  if (!scanResult.safe) {
    lines.push('## Recommendations');
    lines.push('');
    lines.push('- Review flagged files manually');
    lines.push('- Remove confirmed malicious files');
    lines.push('- Restore compromised files from backup');
    lines.push('');
  }

  return lines.join('\n');
}

export function saveChangelog(content: string, filePath: string): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(filePath, content, 'utf-8');
}
