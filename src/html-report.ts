import * as fs from 'fs';
import * as path from 'path';
import { ScanResult, Threat } from './malware-scanner';
import { Vulnerability } from './vulnerability-scanner';
import { IntegrityResult } from './file-integrity';

export interface HtmlReportData {
  timestamp: string;
  scanPath: string;
  scanResult: ScanResult;
  vulnerabilities?: Vulnerability[];
  integrity?: IntegrityResult;
  suggestions: string[];
}

type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

function getSeverityForThreatType(type: string): SeverityLevel {
  if (type.includes('shell_exec') || type.includes('system') || type.includes('passthru') ||
      type.includes('exec') || type.includes('proc_open') || type.includes('popen') ||
      type.includes('pcntl_exec') || type.includes('webshell')) {
    return 'critical';
  }
  if (type.includes('eval') || type.includes('assert') || type.includes('create_function') ||
      type.includes('preg_replace') || type.includes('child_process')) {
    return 'high';
  }
  if (type.includes('base64') || type.includes('gzinflate') || type.includes('gzuncompress') ||
      type.includes('str_rot13') || type.includes('encoded') || type.includes('dynamic')) {
    return 'medium';
  }
  if (type.includes('curl_exec') || type.includes('call_user_func') || type.includes('document_write')) {
    return 'medium';
  }
  if (type.includes('parameter') || type.includes('traversal') || type.includes('suspicious')) {
    return 'low';
  }
  return 'info';
}

function getSeverityColor(severity: SeverityLevel): string {
  const colors: Record<SeverityLevel, string> = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#d97706',
    low: '#ca8a04',
    info: '#2563eb',
  };
  return colors[severity];
}

function getSeverityBgColor(severity: SeverityLevel): string {
  const colors: Record<SeverityLevel, string> = {
    critical: '#fef2f2',
    high: '#fff7ed',
    medium: '#fffbeb',
    low: '#fefce8',
    info: '#eff6ff',
  };
  return colors[severity];
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function formatTimestamp(isoTimestamp: string): string {
  try {
    const date = new Date(isoTimestamp);
    return date.toLocaleString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      timeZoneName: 'short',
    });
  } catch {
    return isoTimestamp;
  }
}

function generateThreatRow(threat: Threat): string {
  const severity = getSeverityForThreatType(threat.type);
  const color = getSeverityColor(severity);
  const bgColor = getSeverityBgColor(severity);
  const lineInfo = threat.line !== null ? `:${threat.line}` : '';

  return `
    <tr style="background-color: ${bgColor};">
      <td style="padding: 12px; border-bottom: 1px solid #e5e7eb;">
        <code style="font-size: 13px; color: #374151;">${escapeHtml(threat.file)}${lineInfo}</code>
      </td>
      <td style="padding: 12px; border-bottom: 1px solid #e5e7eb;">
        <span style="
          display: inline-block;
          padding: 2px 8px;
          border-radius: 4px;
          font-size: 12px;
          font-weight: 600;
          text-transform: uppercase;
          color: ${color};
          border: 1px solid ${color};
        ">${severity}</span>
      </td>
      <td style="padding: 12px; border-bottom: 1px solid #e5e7eb;">
        <code style="font-size: 13px; color: #6b7280;">${escapeHtml(threat.type)}</code>
      </td>
      <td style="padding: 12px; border-bottom: 1px solid #e5e7eb;">
        <code style="font-size: 12px; color: #9ca3af; word-break: break-all;">${escapeHtml(threat.signature)}</code>
      </td>
    </tr>`;
}

function generateSummaryStats(scanResult: ScanResult): string {
  const threatCount = scanResult.threats.length;
  const criticalCount = scanResult.threats.filter(t => getSeverityForThreatType(t.type) === 'critical').length;
  const highCount = scanResult.threats.filter(t => getSeverityForThreatType(t.type) === 'high').length;
  const mediumCount = scanResult.threats.filter(t => getSeverityForThreatType(t.type) === 'medium').length;
  const lowCount = scanResult.threats.filter(t => getSeverityForThreatType(t.type) === 'low').length;

  const statCards = [
    { label: 'Total Files', value: scanResult.totalFiles, color: '#6366f1' },
    { label: 'Threats Found', value: threatCount, color: threatCount > 0 ? '#dc2626' : '#16a34a' },
    { label: 'Critical', value: criticalCount, color: '#dc2626' },
    { label: 'High', value: highCount, color: '#ea580c' },
    { label: 'Medium', value: mediumCount, color: '#d97706' },
    { label: 'Low', value: lowCount, color: '#ca8a04' },
  ];

  return statCards.map(card => `
    <div style="
      flex: 1;
      min-width: 140px;
      padding: 20px;
      background: white;
      border-radius: 8px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
      text-align: center;
    ">
      <div style="font-size: 32px; font-weight: 700; color: ${card.color};">${card.value}</div>
      <div style="font-size: 14px; color: #6b7280; margin-top: 4px;">${card.label}</div>
    </div>
  `).join('');
}

function generateVulnerabilitySection(vulnerabilities: Vulnerability[]): string {
  if (vulnerabilities.length === 0) {
    return '';
  }

  const rows = vulnerabilities.map(vuln => {
    const severityColor = getSeverityColor(vuln.severity as SeverityLevel);
    return `
      <tr>
        <td style="padding: 12px; border-bottom: 1px solid #e5e7eb;">${escapeHtml(vuln.component)}</td>
        <td style="padding: 12px; border-bottom: 1px solid #e5e7eb;">${escapeHtml(vuln.version)}</td>
        <td style="padding: 12px; border-bottom: 1px solid #e5e7eb;">
          <span style="color: ${severityColor}; font-weight: 600;">${escapeHtml(vuln.severity)}</span>
        </td>
        <td style="padding: 12px; border-bottom: 1px solid #e5e7eb;">${escapeHtml(vuln.title)}</td>
        <td style="padding: 12px; border-bottom: 1px solid #e5e7eb;">
          <code style="font-size: 12px;">${escapeHtml(vuln.cve)}</code>
        </td>
      </tr>`;
  }).join('');

  return `
    <div style="margin-top: 32px;">
      <h2 style="font-size: 20px; font-weight: 600; color: #1f2937; margin-bottom: 16px;">
        Known Vulnerabilities
      </h2>
      <div style="overflow-x: auto;">
        <table style="width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
          <thead>
            <tr style="background-color: #f9fafb;">
              <th style="padding: 12px; text-align: left; font-weight: 600; color: #374151; border-bottom: 2px solid #e5e7eb;">Component</th>
              <th style="padding: 12px; text-align: left; font-weight: 600; color: #374151; border-bottom: 2px solid #e5e7eb;">Version</th>
              <th style="padding: 12px; text-align: left; font-weight: 600; color: #374151; border-bottom: 2px solid #e5e7eb;">Severity</th>
              <th style="padding: 12px; text-align: left; font-weight: 600; color: #374151; border-bottom: 2px solid #e5e7eb;">Title</th>
              <th style="padding: 12px; text-align: left; font-weight: 600; color: #374151; border-bottom: 2px solid #e5e7eb;">CVE</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>`;
}

function generateIntegritySection(integrity: IntegrityResult): string {
  if (!integrity.wordpressVersion && integrity.checked === 0) {
    return '';
  }

  let modifiedFilesHtml = '';
  if (integrity.modifiedFiles.length > 0) {
    const fileList = integrity.modifiedFiles.map(f =>
      `<li style="padding: 4px 0; color: #dc2626; font-family: monospace; font-size: 13px;">${escapeHtml(f)}</li>`
    ).join('');
    modifiedFilesHtml = `
      <div style="margin-top: 12px; padding: 12px; background: #fef2f2; border-radius: 6px; border: 1px solid #fecaca;">
        <strong style="color: #dc2626;">Modified Core Files:</strong>
        <ul style="margin: 8px 0 0 0; padding-left: 20px;">${fileList}</ul>
      </div>`;
  }

  return `
    <div style="margin-top: 32px;">
      <h2 style="font-size: 20px; font-weight: 600; color: #1f2937; margin-bottom: 16px;">
        File Integrity Check
      </h2>
      <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
        <div style="display: flex; gap: 32px; flex-wrap: wrap;">
          ${integrity.wordpressVersion ? `
            <div>
              <div style="font-size: 14px; color: #6b7280;">WordPress Version</div>
              <div style="font-size: 18px; font-weight: 600; color: #1f2937;">${escapeHtml(integrity.wordpressVersion)}</div>
            </div>
          ` : ''}
          <div>
            <div style="font-size: 14px; color: #6b7280;">Files Checked</div>
            <div style="font-size: 18px; font-weight: 600; color: #1f2937;">${integrity.checked}</div>
          </div>
          <div>
            <div style="font-size: 14px; color: #6b7280;">Modified Files</div>
            <div style="font-size: 18px; font-weight: 600; color: ${integrity.modified > 0 ? '#dc2626' : '#16a34a'};">${integrity.modified}</div>
          </div>
        </div>
        ${modifiedFilesHtml}
      </div>
    </div>`;
}

function generateSuggestionsSection(suggestions: string[]): string {
  if (suggestions.length === 0) {
    return '';
  }

  const items = suggestions.map(s =>
    `<li style="padding: 8px 0; color: #374151;">${escapeHtml(s)}</li>`
  ).join('');

  return `
    <div style="margin-top: 32px;">
      <h2 style="font-size: 20px; font-weight: 600; color: #1f2937; margin-bottom: 16px;">
        Recommendations
      </h2>
      <div style="background: #eff6ff; padding: 20px; border-radius: 8px; border: 1px solid #bfdbfe;">
        <ul style="margin: 0; padding-left: 20px;">${items}</ul>
      </div>
    </div>`;
}

export function generateHtmlReport(data: HtmlReportData): string {
  const { timestamp, scanPath, scanResult, vulnerabilities, integrity, suggestions } = data;

  const statusColor = scanResult.safe ? '#16a34a' : '#dc2626';
  const statusText = scanResult.safe ? 'SAFE' : 'THREATS DETECTED';
  const statusBg = scanResult.safe ? '#f0fdf4' : '#fef2f2';
  const statusBorder = scanResult.safe ? '#bbf7d0' : '#fecaca';

  const threatRows = scanResult.threats.map(generateThreatRow).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Clean Sweep Security Report</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f3f4f6; color: #1f2937; }
    .container { max-width: 1200px; margin: 0 auto; padding: 24px; }
    @media (max-width: 768px) {
      .container { padding: 12px; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div style="background: linear-gradient(135deg, #1e293b 0%, #334155 100%); color: white; padding: 32px; border-radius: 12px; margin-bottom: 24px;">
      <h1 style="font-size: 28px; font-weight: 700; margin-bottom: 8px;">Clean Sweep Security Report</h1>
      <div style="font-size: 14px; color: #94a3b8;">
        <div>Scan Path: <code style="color: #e2e8f0;">${escapeHtml(scanPath)}</code></div>
        <div>Generated: ${escapeHtml(formatTimestamp(timestamp))}</div>
      </div>
    </div>

    <div style="
      display: inline-block;
      padding: 12px 24px;
      background: ${statusBg};
      border: 2px solid ${statusBorder};
      border-radius: 8px;
      margin-bottom: 24px;
    ">
      <span style="font-size: 18px; font-weight: 700; color: ${statusColor};">
        Status: ${statusText}
      </span>
    </div>

    <div style="display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 32px;">
      ${generateSummaryStats(scanResult)}
    </div>

    ${scanResult.threats.length > 0 ? `
      <div style="margin-bottom: 32px;">
        <h2 style="font-size: 20px; font-weight: 600; color: #1f2937; margin-bottom: 16px;">
          Threats Found (${scanResult.threats.length})
        </h2>
        <div style="overflow-x: auto;">
          <table style="width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
            <thead>
              <tr style="background-color: #f9fafb;">
                <th style="padding: 12px; text-align: left; font-weight: 600; color: #374151; border-bottom: 2px solid #e5e7eb;">File</th>
                <th style="padding: 12px; text-align: left; font-weight: 600; color: #374151; border-bottom: 2px solid #e5e7eb;">Severity</th>
                <th style="padding: 12px; text-align: left; font-weight: 600; color: #374151; border-bottom: 2px solid #e5e7eb;">Type</th>
                <th style="padding: 12px; text-align: left; font-weight: 600; color: #374151; border-bottom: 2px solid #e5e7eb;">Signature</th>
              </tr>
            </thead>
            <tbody>${threatRows}</tbody>
          </table>
        </div>
      </div>
    ` : `
      <div style="
        padding: 24px;
        background: #f0fdf4;
        border: 1px solid #bbf7d0;
        border-radius: 8px;
        margin-bottom: 32px;
      ">
        <p style="font-size: 16px; color: #16a34a; font-weight: 600;">
          No threats detected. The scanned directory appears clean.
        </p>
      </div>
    `}

    ${vulnerabilities ? generateVulnerabilitySection(vulnerabilities) : ''}
    ${integrity ? generateIntegritySection(integrity) : ''}
    ${generateSuggestionsSection(suggestions)}

    <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #e5e7eb; text-align: center; color: #9ca3af; font-size: 12px;">
      Generated by Clean Sweep CLI &mdash; ${escapeHtml(formatTimestamp(timestamp))}
    </div>
  </div>
</body>
</html>`;
}

export function getDefaultHtmlReportPath(scanPath: string): string {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const safePath = scanPath.replace(/[^a-zA-Z0-9]/g, '_').substring(0, 50);
  return path.join('reports', `scan-${safePath}-${timestamp}.html`);
}

export function saveHtmlReport(html: string, filePath: string): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(filePath, html, 'utf-8');
}
