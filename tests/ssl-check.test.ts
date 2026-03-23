import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import * as tls from 'tls';
import { Command } from 'commander';

jest.mock('tls');

import {
  parseCertificate,
  checkSslCertificate,
  registerSslCheckCommand,
  SslCheckResult,
} from '../src/commands/ssl-check';

function createTestCliOptions(
  overrides: Partial<{
    dryRun: boolean;
    force: boolean;
    json: boolean;
    path: string;
    verbose: boolean;
    logLevel: string;
  }> = {}
) {
  return () => ({
    dryRun: true,
    force: false,
    json: false,
    path: process.cwd(),
    verbose: false,
    logLevel: 'error' as string,
    checkVulnerabilities: false,
    checkIntegrity: false,
    findUnknown: false,
    report: false,
    ...overrides,
  });
}

function createProgram() {
  const program = new Command();
  program.exitOverride();
  return program;
}

function createMockCertificate(overrides: Partial<tls.PeerCertificate> = {}): tls.PeerCertificate {
  const now = new Date();
  const future = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);
  return {
    subject: { CN: 'example.com', O: 'Example Org', C: 'US' },
    issuer: { CN: 'Test CA', O: 'Test CA Org' },
    valid_from: now.toUTCString(),
    valid_to: future.toUTCString(),
    serialNumber: 'ABCDEF1234567890',
    fingerprint: 'SHA256:1234567890ABCDEF',
    subjectaltname: 'DNS:example.com, DNS:www.example.com',
    ...overrides,
  } as unknown as tls.PeerCertificate;
}

function createMockSocket(certificate: tls.PeerCertificate | null, protocol: string | null = 'TLSv1.3') {
  const listeners: Record<string, Function> = {};
  return {
    getPeerCertificate: jest.fn(() => certificate),
    getProtocol: jest.fn(() => protocol),
    destroy: jest.fn(),
    on: jest.fn((event: string, handler: Function) => {
      listeners[event] = handler;
    }),
    setTimeout: jest.fn(),
    _trigger: (event: string, ...args: any[]) => {
      if (listeners[event]) {
        listeners[event](...args);
      }
    },
  };
}

describe('SSL Check Module', () => {
  let consoleSpy: ReturnType<typeof jest.spyOn>;
  let consoleErrorSpy: ReturnType<typeof jest.spyOn>;
  let mockConnect: any;

  beforeEach(() => {
    jest.resetAllMocks();
    consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    mockConnect = tls.connect as any;
  });

  afterEach(() => {
    consoleSpy.mockRestore();
    consoleErrorSpy.mockRestore();
  });

  describe('parseCertificate', () => {
    it('should parse a valid certificate correctly', () => {
      const cert = createMockCertificate();
      const result = parseCertificate(cert, 'TLSv1.3');

      expect(result.subject).toContain('CN=example.com');
      expect(result.issuer).toContain('CN=Test CA');
      expect(result.serialNumber).toBe('ABCDEF1234567890');
      expect(result.fingerprint).toBe('SHA256:1234567890ABCDEF');
      expect(result.subjectAltNames).toEqual(['example.com', 'www.example.com']);
      expect(result.isValid).toBe(true);
      expect(result.isExpired).toBe(false);
      expect(result.daysUntilExpiry).toBeGreaterThan(0);
      expect(result.chainValid).toBe(true);
      expect(result.protocol).toBe('TLSv1.3');
      expect(result.error).toBeNull();
    });

    it('should detect expired certificates', () => {
      const past = new Date(Date.now() - 24 * 60 * 60 * 1000);
      const cert = createMockCertificate({ valid_to: past.toUTCString() });
      const result = parseCertificate(cert, 'TLSv1.2');

      expect(result.isExpired).toBe(true);
      expect(result.daysUntilExpiry).toBeLessThan(0);
      expect(result.chainValid).toBe(false);
    });

    it('should handle certificates with no subjectAltNames', () => {
      const cert = createMockCertificate({ subjectaltname: '' } as any);
      const result = parseCertificate(cert, 'TLSv1.3');

      expect(result.subjectAltNames).toEqual([]);
    });

    it('should handle certificates expiring within 30 days', () => {
      const soonDate = new Date(Date.now() + 15 * 24 * 60 * 60 * 1000);
      const cert = createMockCertificate({ valid_to: soonDate.toUTCString() });
      const result = parseCertificate(cert, 'TLSv1.3');

      expect(result.isExpired).toBe(false);
      expect(result.daysUntilExpiry).toBeLessThanOrEqual(15);
      expect(result.daysUntilExpiry).toBeGreaterThan(0);
    });

    it('should handle null protocol', () => {
      const cert = createMockCertificate();
      const result = parseCertificate(cert, null);

      expect(result.protocol).toBeNull();
    });

    it('should parse subjectAltNames with mixed DNS entries', () => {
      const cert = createMockCertificate({
        subjectaltname: 'DNS:*.example.com, DNS:example.com, IP:1.2.3.4',
      } as any);
      const result = parseCertificate(cert, 'TLSv1.3');

      expect(result.subjectAltNames).toEqual(['*.example.com', 'example.com']);
    });
  });

  describe('checkSslCertificate', () => {
    it('should return success when connection succeeds with valid certificate', async () => {
      const cert = createMockCertificate();
      const mockSocket = createMockSocket(cert);

      mockConnect.mockImplementation((_opts: any, callback: Function) => {
        process.nextTick(() => callback());
        return mockSocket;
      });

      const result = await checkSslCertificate('example.com', 443, 5000);

      expect(result.success).toBe(true);
      expect(result.host).toBe('example.com');
      expect(result.port).toBe(443);
      expect(result.certificate).not.toBeNull();
      expect(result.certificate!.subject).toContain('CN=example.com');
      expect(result.certificate!.protocol).toBe('TLSv1.3');
      expect(result.error).toBeNull();
      expect(mockSocket.destroy).toHaveBeenCalled();
    });

    it('should return error when connection fails', async () => {
      const mockSocket = createMockSocket(null);

      mockConnect.mockImplementation((_opts: any, _callback: Function) => {
        process.nextTick(() => mockSocket._trigger('error', new Error('ECONNREFUSED')));
        return mockSocket;
      });

      const result = await checkSslCertificate('badhost.invalid', 443, 5000);

      expect(result.success).toBe(false);
      expect(result.error).toBe('ECONNREFUSED');
      expect(result.certificate).toBeNull();
      expect(mockSocket.destroy).toHaveBeenCalled();
    });

    it('should return error when connection times out', async () => {
      const mockSocket = createMockSocket(null);

      mockConnect.mockImplementation((_opts: any, _callback: Function) => {
        process.nextTick(() => mockSocket._trigger('timeout'));
        return mockSocket;
      });

      const result = await checkSslCertificate('slowhost.example.com', 443, 3000);

      expect(result.success).toBe(false);
      expect(result.error).toContain('timed out');
      expect(result.error).toContain('3000ms');
      expect(result.certificate).toBeNull();
      expect(mockSocket.destroy).toHaveBeenCalled();
    });

    it('should return error when no certificate is returned', async () => {
      const mockSocket = createMockSocket({} as tls.PeerCertificate);

      mockConnect.mockImplementation((_opts: any, callback: Function) => {
        process.nextTick(() => callback());
        return mockSocket;
      });

      const result = await checkSslCertificate('example.com', 443, 5000);

      expect(result.success).toBe(false);
      expect(result.error).toBe('No certificate returned by server');
      expect(mockSocket.destroy).toHaveBeenCalled();
    });

    it('should use correct port and host in connection options', async () => {
      const cert = createMockCertificate();
      const mockSocket = createMockSocket(cert);

      mockConnect.mockImplementation((opts: any, callback: Function) => {
        process.nextTick(() => callback());
        return mockSocket;
      });

      await checkSslCertificate('test.example.com', 8443, 7000);

      expect(mockConnect).toHaveBeenCalledWith(
        expect.objectContaining({ host: 'test.example.com', port: 8443, timeout: 7000 }),
        expect.any(Function)
      );
    });
  });

  describe('registerSslCheckCommand', () => {
    it('should register ssl:check command on program', () => {
      const program = createProgram();
      registerSslCheckCommand(program, createTestCliOptions());

      const cmd = program.commands.find((c) => c.name() === 'ssl:check');
      expect(cmd).toBeDefined();
      expect(cmd!.description()).toContain('SSL certificate');
    });

    it('should require --host option', () => {
      const program = createProgram();
      registerSslCheckCommand(program, createTestCliOptions());

      const cmd = program.commands.find((c) => c.name() === 'ssl:check');
      const requiredOpts = cmd!.options.filter((o) => o.required);
      expect(requiredOpts.some((o) => o.long === '--host')).toBe(true);
    });

    it('should support --json option', () => {
      const program = createProgram();
      registerSslCheckCommand(program, createTestCliOptions());

      const cmd = program.commands.find((c) => c.name() === 'ssl:check');
      const jsonOpt = cmd!.options.find((o) => o.long === '--json');
      expect(jsonOpt).toBeDefined();
    });

    it('should support --port option with default 443', () => {
      const program = createProgram();
      registerSslCheckCommand(program, createTestCliOptions());

      const cmd = program.commands.find((c) => c.name() === 'ssl:check');
      const portOpt = cmd!.options.find((o) => o.long === '--port');
      expect(portOpt).toBeDefined();
      expect(portOpt!.defaultValue).toBe('443');
    });

    it('should support --timeout option with default 10000', () => {
      const program = createProgram();
      registerSslCheckCommand(program, createTestCliOptions());

      const cmd = program.commands.find((c) => c.name() === 'ssl:check');
      const timeoutOpt = cmd!.options.find((o) => o.long === '--timeout');
      expect(timeoutOpt).toBeDefined();
      expect(timeoutOpt!.defaultValue).toBe('10000');
    });

    it('should output JSON when --json flag is used', async () => {
      const cert = createMockCertificate();
      const mockSocket = createMockSocket(cert);

      mockConnect.mockImplementation((_opts: any, callback: Function) => {
        process.nextTick(() => callback());
        return mockSocket;
      });

      const program = createProgram();
      registerSslCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync(['node', 'test', 'ssl:check', '--host', 'example.com', '--json']);
      } catch {
        // exitOverride may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);

      expect(result).toHaveProperty('host', 'example.com');
      expect(result).toHaveProperty('port', 443);
      expect(result).toHaveProperty('certificate');
      expect(result).toHaveProperty('success', true);
      expect(result.certificate).toHaveProperty('subject');
      expect(result.certificate).toHaveProperty('issuer');
      expect(result.certificate).toHaveProperty('validFrom');
      expect(result.certificate).toHaveProperty('validTo');
      expect(result.certificate).toHaveProperty('daysUntilExpiry');
      expect(result.certificate).toHaveProperty('isExpired', false);
      expect(result.certificate).toHaveProperty('chainValid', true);
      mockExit.mockRestore();
    });

    it('should output human-readable format without --json', async () => {
      const cert = createMockCertificate();
      const mockSocket = createMockSocket(cert);

      mockConnect.mockImplementation((_opts: any, callback: Function) => {
        process.nextTick(() => callback());
        return mockSocket;
      });

      const program = createProgram();
      registerSslCheckCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync(['node', 'test', 'ssl:check', '--host', 'example.com']);
      } catch {
        // exitOverride may throw
      }

      const allOutput = consoleSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('SSL Certificate Check');
      expect(allOutput).toContain('example.com');
      expect(allOutput).toContain('Subject:');
      expect(allOutput).toContain('Issuer:');
      expect(allOutput).toContain('VALID');
      mockExit.mockRestore();
    });

    it('should exit 0 when certificate is valid and not expiring soon', async () => {
      const futureDate = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000);
      const cert = createMockCertificate({ valid_to: futureDate.toUTCString() });
      const mockSocket = createMockSocket(cert);

      mockConnect.mockImplementation((_opts: any, callback: Function) => {
        process.nextTick(() => callback());
        return mockSocket;
      });

      const program = createProgram();
      registerSslCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync(['node', 'test', 'ssl:check', '--host', 'example.com', '--json']);
      } catch {
        // exitOverride may throw
      }

      expect(mockExit).toHaveBeenCalledWith(0);
      mockExit.mockRestore();
    });

    it('should exit 1 when certificate is expired', async () => {
      const pastDate = new Date(Date.now() - 24 * 60 * 60 * 1000);
      const cert = createMockCertificate({ valid_to: pastDate.toUTCString() });
      const mockSocket = createMockSocket(cert);

      mockConnect.mockImplementation((_opts: any, callback: Function) => {
        process.nextTick(() => callback());
        return mockSocket;
      });

      const program = createProgram();
      registerSslCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync(['node', 'test', 'ssl:check', '--host', 'example.com', '--json']);
      } catch {
        // exitOverride may throw
      }

      expect(mockExit).toHaveBeenCalledWith(1);
      mockExit.mockRestore();
    });

    it('should exit 1 when connection fails', async () => {
      const mockSocket = createMockSocket(null);

      mockConnect.mockImplementation((_opts: any, _callback: Function) => {
        process.nextTick(() => mockSocket._trigger('error', new Error('Connection failed')));
        return mockSocket;
      });

      const program = createProgram();
      registerSslCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync(['node', 'test', 'ssl:check', '--host', 'badhost.invalid', '--json']);
      } catch {
        // exitOverride may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);
      expect(result.success).toBe(false);
      expect(result.error).toBe('Connection failed');
      expect(mockExit).toHaveBeenCalledWith(1);
      mockExit.mockRestore();
    });

    it('should exit 1 with error message for invalid port', async () => {
      const program = createProgram();
      registerSslCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync(['node', 'test', 'ssl:check', '--host', 'example.com', '--port', '99999', '--json']);
      } catch {
        // exitOverride may throw
      }

      expect(mockExit).toHaveBeenCalledWith(1);
      mockExit.mockRestore();
    });

    it('should show EXPIRING SOON status for certificates expiring within 30 days', async () => {
      const soonDate = new Date(Date.now() + 10 * 24 * 60 * 60 * 1000);
      const cert = createMockCertificate({ valid_to: soonDate.toUTCString() });
      const mockSocket = createMockSocket(cert);

      mockConnect.mockImplementation((_opts: any, callback: Function) => {
        process.nextTick(() => callback());
        return mockSocket;
      });

      const program = createProgram();
      registerSslCheckCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync(['node', 'test', 'ssl:check', '--host', 'example.com']);
      } catch {
        // exitOverride may throw
      }

      const allOutput = consoleSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('EXPIRING SOON');
      mockExit.mockRestore();
    });

    it('should show EXPIRED status in human-readable output', async () => {
      const pastDate = new Date(Date.now() - 5 * 24 * 60 * 60 * 1000);
      const cert = createMockCertificate({ valid_to: pastDate.toUTCString() });
      const mockSocket = createMockSocket(cert);

      mockConnect.mockImplementation((_opts: any, callback: Function) => {
        process.nextTick(() => callback());
        return mockSocket;
      });

      const program = createProgram();
      registerSslCheckCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync(['node', 'test', 'ssl:check', '--host', 'example.com']);
      } catch {
        // exitOverride may throw
      }

      const allOutput = consoleSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('EXPIRED');
      mockExit.mockRestore();
    });

    it('should show connection error in human-readable output', async () => {
      const mockSocket = createMockSocket(null);

      mockConnect.mockImplementation((_opts: any, _callback: Function) => {
        process.nextTick(() => mockSocket._trigger('error', new Error('ECONNREFUSED')));
        return mockSocket;
      });

      const program = createProgram();
      registerSslCheckCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync(['node', 'test', 'ssl:check', '--host', 'badhost.invalid']);
      } catch {
        // exitOverride may throw
      }

      const allOutput = consoleSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('Error:');
      expect(allOutput).toContain('ECONNREFUSED');
      mockExit.mockRestore();
    });

    it('should produce valid JSON for all error cases', async () => {
      const mockSocket = createMockSocket(null);

      mockConnect.mockImplementation((_opts: any, _callback: Function) => {
        process.nextTick(() => mockSocket._trigger('error', new Error('SSL handshake failed')));
        return mockSocket;
      });

      const program = createProgram();
      registerSslCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync(['node', 'test', 'ssl:check', '--host', 'badhost.invalid', '--json']);
      } catch {
        // exitOverride may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      expect(() => JSON.parse(output)).not.toThrow();

      const result = JSON.parse(output);
      expect(result.success).toBe(false);
      expect(result.host).toBe('badhost.invalid');
      expect(result.certificate).toBeNull();
      expect(result.error).toBe('SSL handshake failed');
      mockExit.mockRestore();
    });

    it('should display SANs in human-readable output when present', async () => {
      const cert = createMockCertificate();
      const mockSocket = createMockSocket(cert);

      mockConnect.mockImplementation((_opts: any, callback: Function) => {
        process.nextTick(() => callback());
        return mockSocket;
      });

      const program = createProgram();
      registerSslCheckCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync(['node', 'test', 'ssl:check', '--host', 'example.com']);
      } catch {
        // exitOverride may throw
      }

      const allOutput = consoleSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('SANs:');
      expect(allOutput).toContain('example.com');
      mockExit.mockRestore();
    });

    it('should output invalid port error in human-readable format', async () => {
      const program = createProgram();
      registerSslCheckCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync(['node', 'test', 'ssl:check', '--host', 'example.com', '--port', '0']);
      } catch {
        // exitOverride may throw
      }

      expect(consoleErrorSpy).toHaveBeenCalledWith(expect.stringContaining('Invalid port'));
      expect(mockExit).toHaveBeenCalledWith(1);
      mockExit.mockRestore();
    });
  });
});
