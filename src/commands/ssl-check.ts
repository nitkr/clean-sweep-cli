import { Command } from 'commander';
import * as tls from 'tls';

export interface CertificateInfo {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  serialNumber: string;
  fingerprint: string;
  subjectAltNames: string[];
  isValid: boolean;
  daysUntilExpiry: number;
  isExpired: boolean;
  chainValid: boolean;
  protocol: string | null;
  error: string | null;
}

export interface SslCheckResult {
  host: string;
  port: number;
  certificate: CertificateInfo | null;
  success: boolean;
  error: string | null;
}

export function parseCertificate(cert: tls.PeerCertificate, protocol: string | null): CertificateInfo {
  const now = new Date();
  const validFrom = new Date(cert.valid_from);
  const validTo = new Date(cert.valid_to);
  const daysUntilExpiry = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
  const isExpired = daysUntilExpiry < 0;

  const subjectAltNames: string[] = [];
  if (cert.subjectaltname) {
    const matches = cert.subjectaltname.match(/DNS:([^,\s]+)/g);
    if (matches) {
      for (const match of matches) {
        subjectAltNames.push(match.replace('DNS:', ''));
      }
    }
  }

  return {
    subject: formatDn(cert.subject),
    issuer: formatDn(cert.issuer),
    validFrom: validFrom.toISOString(),
    validTo: validTo.toISOString(),
    serialNumber: cert.serialNumber || '',
    fingerprint: cert.fingerprint || '',
    subjectAltNames,
    isValid: cert.valid_to !== undefined,
    daysUntilExpiry,
    isExpired,
    chainValid: !isExpired,
    protocol,
    error: null,
  };
}

function formatDn(dn: tls.Certificate | undefined): string {
  if (!dn) return '';
  const parts: string[] = [];
  for (const [key, value] of Object.entries(dn)) {
    if (typeof value === 'string') {
      parts.push(`${key}=${value}`);
    } else if (Array.isArray(value)) {
      parts.push(`${key}=${value.join(', ')}`);
    }
  }
  return parts.join(', ');
}

export function checkSslCertificate(host: string, port: number, timeout: number = 10000): Promise<SslCheckResult> {
  return new Promise((resolve) => {
    let settled = false;

    const settle = (result: SslCheckResult) => {
      if (!settled) {
        settled = true;
        resolve(result);
      }
    };

    const socket = tls.connect(
      {
        host,
        port,
        rejectUnauthorized: false,
        timeout,
      },
      () => {
        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol();

        if (!cert || Object.keys(cert).length === 0) {
          socket.destroy();
          settle({
            host,
            port,
            certificate: null,
            success: false,
            error: 'No certificate returned by server',
          });
          return;
        }

        const certInfo = parseCertificate(cert, protocol);
        socket.destroy();
        settle({
          host,
          port,
          certificate: certInfo,
          success: true,
          error: null,
        });
      }
    );

    socket.on('error', (err: Error) => {
      socket.destroy();
      settle({
        host,
        port,
        certificate: null,
        success: false,
        error: err.message,
      });
    });

    socket.on('timeout', () => {
      socket.destroy();
      settle({
        host,
        port,
        certificate: null,
        success: false,
        error: `Connection timed out after ${timeout}ms`,
      });
    });

    socket.setTimeout(timeout);
  });
}

export function registerSslCheckCommand(
  program: Command,
  getOpts: () => {
    dryRun: boolean;
    force: boolean;
    json: boolean;
    path: string;
    verbose: boolean;
    logLevel: string;
  }
): void {
  program
    .command('ssl:check')
    .description('Check SSL certificate validity, expiration, and chain for a host')
    .requiredOption('--host <host>', 'Hostname to check SSL certificate for')
    .option('--port <port>', 'Port to connect on', '443')
    .option('--json', 'Output results as JSON', false)
    .option('--timeout <ms>', 'Connection timeout in milliseconds', '10000')
    .action(async (cmdOptions) => {
      const opts = getOpts();
      const useJson = cmdOptions.json || opts.json;
      const port = parseInt(cmdOptions.port, 10);
      const timeout = parseInt(cmdOptions.timeout, 10);

      if (isNaN(port) || port < 1 || port > 65535) {
        const error = { error: 'Invalid port number. Must be between 1 and 65535.' };
        if (useJson) {
          console.log(JSON.stringify(error, null, 2));
        } else {
          console.error(error.error);
        }
        process.exit(1);
      }

      if (isNaN(timeout) || timeout < 1) {
        const error = { error: 'Invalid timeout value.' };
        if (useJson) {
          console.log(JSON.stringify(error, null, 2));
        } else {
          console.error(error.error);
        }
        process.exit(1);
      }

      const result = await checkSslCertificate(cmdOptions.host, port, timeout);

      if (useJson) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.log(`SSL Certificate Check: ${result.host}:${result.port}`);
        console.log('');

        if (!result.success) {
          console.log(`  Error: ${result.error}`);
          process.exit(1);
          return;
        }

        const cert = result.certificate!;
        console.log(`  Subject:       ${cert.subject}`);
        console.log(`  Issuer:        ${cert.issuer}`);
        console.log(`  Valid From:    ${cert.validFrom}`);
        console.log(`  Valid To:      ${cert.validTo}`);
        console.log(`  Days Until Expiry: ${cert.daysUntilExpiry}`);
        console.log(`  Serial Number: ${cert.serialNumber}`);
        console.log(`  Fingerprint:   ${cert.fingerprint}`);
        console.log(`  Protocol:      ${cert.protocol || 'Unknown'}`);

        if (cert.subjectAltNames.length > 0) {
          console.log(`  SANs:          ${cert.subjectAltNames.join(', ')}`);
        }

        console.log('');
        console.log('  Status:');
        if (cert.isExpired) {
          console.log('    Certificate: EXPIRED');
        } else if (cert.daysUntilExpiry <= 30) {
          console.log(`    Certificate: EXPIRING SOON (${cert.daysUntilExpiry} days remaining)`);
        } else {
          console.log('    Certificate: VALID');
        }
        console.log(`    Chain:       ${cert.chainValid ? 'VALID' : 'INVALID'}`);
      }

      if (!result.success || result.certificate?.isExpired || !result.certificate?.chainValid) {
        process.exit(1);
      }

      process.exit(0);
    });
}
