import * as path from 'path';
import * as fs from 'fs';
import { Threat } from './malware-scanner';

export interface WhitelistConfig {
  version: string;
  description: string;
  lastUpdated: string;
  paths: string[];
  signatures: string[];
  extensions: string[];
}

const SIGNATURES_DIR = path.resolve(__dirname, '..', 'signatures');

export function loadWhitelist(whitelistPath?: string): WhitelistConfig {
  const resolvedPath = whitelistPath || path.join(SIGNATURES_DIR, 'whitelist.json');

  if (!fs.existsSync(resolvedPath)) {
    return {
      version: '1.0.0',
      description: 'Empty whitelist',
      lastUpdated: '',
      paths: [],
      signatures: [],
      extensions: [],
    };
  }

  const raw = JSON.parse(fs.readFileSync(resolvedPath, 'utf-8')) as Partial<WhitelistConfig>;

  return {
    version: raw.version || '1.0.0',
    description: raw.description || '',
    lastUpdated: raw.lastUpdated || '',
    paths: Array.isArray(raw.paths) ? raw.paths : [],
    signatures: Array.isArray(raw.signatures) ? raw.signatures : [],
    extensions: Array.isArray(raw.extensions) ? raw.extensions.map(e => e.toLowerCase()) : [],
  };
}

export function isPathWhitelisted(filePath: string, whitelistPaths: string[]): boolean {
  const normalizedFile = path.resolve(filePath);

  for (const wp of whitelistPaths) {
    const normalizedWp = path.resolve(wp);

    if (normalizedFile === normalizedWp) {
      return true;
    }

    if (normalizedFile.startsWith(normalizedWp + path.sep)) {
      return true;
    }

    const wpParts = normalizedWp.split(path.sep);
    const fileParts = normalizedFile.split(path.sep);

    const wpFilename = wpParts[wpParts.length - 1];
    const fileFilename = fileParts[fileParts.length - 1];

    if (wpFilename === fileFilename && wpParts.length === 1) {
      return true;
    }
  }

  return false;
}

export function isSignatureWhitelisted(threatType: string, whitelistSignatures: string[]): boolean {
  return whitelistSignatures.includes(threatType);
}

export function isExtensionWhitelisted(filePath: string, whitelistExtensions: string[]): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return whitelistExtensions.includes(ext);
}

export function filterWhitelistedThreats(
  threats: Threat[],
  filePath: string,
  config: WhitelistConfig
): Threat[] {
  if (isPathWhitelisted(filePath, config.paths)) {
    return [];
  }

  if (isExtensionWhitelisted(filePath, config.extensions)) {
    return [];
  }

  return threats.filter(
    threat => !isSignatureWhitelisted(threat.type, config.signatures)
  );
}

export function applyWhitelist(
  threats: Threat[],
  config: WhitelistConfig
): Threat[] {
  const byFile = new Map<string, Threat[]>();

  for (const threat of threats) {
    const existing = byFile.get(threat.file) || [];
    existing.push(threat);
    byFile.set(threat.file, existing);
  }

  const filtered: Threat[] = [];

  for (const [file, fileThreats] of byFile) {
    filtered.push(...filterWhitelistedThreats(fileThreats, file, config));
  }

  return filtered;
}
