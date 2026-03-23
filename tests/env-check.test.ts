import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { execSync } from 'child_process';
import { Command } from 'commander';

jest.mock('child_process', () => ({
  execSync: jest.fn(),
}));

const mockExecSync = execSync as jest.MockedFunction<typeof execSync>;

import {
  checkPhpVersion,
  checkNodeVersion,
  checkServerSoftware,
  checkEnv,
  registerEnvCheckCommand,
} from '../src/commands/env-check';

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

describe('Env Check Module', () => {
  let consoleSpy: ReturnType<typeof jest.spyOn>;
  let consoleErrorSpy: ReturnType<typeof jest.spyOn>;

  beforeEach(() => {
    mockExecSync.mockReset();
    consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    consoleSpy.mockRestore();
    consoleErrorSpy.mockRestore();
  });

  describe('checkPhpVersion', () => {
    it('should return PHP version when php is available', () => {
      mockExecSync.mockReturnValueOnce(
        'PHP 8.2.10 (cli) (built: Aug 30 2023 00:00:00) ( NTS )\nCopyright (c) The PHP Group\n'
      );

      const result = checkPhpVersion();

      expect(result.name).toBe('PHP');
      expect(result.version).toBe('8.2.10');
      expect(result.available).toBe(true);
      expect(result.details).toContain('PHP 8.2.10');
    });

    it('should return not available when php is not installed', () => {
      mockExecSync.mockImplementationOnce(() => {
        throw new Error('command not found');
      });

      const result = checkPhpVersion();

      expect(result.name).toBe('PHP');
      expect(result.version).toBeNull();
      expect(result.available).toBe(false);
    });

    it('should handle PHP version string without standard format', () => {
      mockExecSync.mockReturnValueOnce('SomeCustomPHP 7.4');

      const result = checkPhpVersion();

      expect(result.available).toBe(false);
      expect(result.version).toBeNull();
    });

    it('should handle empty output from php -v', () => {
      mockExecSync.mockReturnValueOnce('');

      const result = checkPhpVersion();

      expect(result.available).toBe(false);
      expect(result.version).toBeNull();
    });

    it('should extract version from PHP 7.x output', () => {
      mockExecSync.mockReturnValueOnce(
        'PHP 7.4.33 (cli) (built: Sep  2 2022 13:22:24) ( NTS )\n'
      );

      const result = checkPhpVersion();

      expect(result.version).toBe('7.4.33');
      expect(result.available).toBe(true);
    });
  });

  describe('checkNodeVersion', () => {
    it('should return the current Node.js version', () => {
      const result = checkNodeVersion();

      expect(result.name).toBe('Node.js');
      expect(result.version).toBe(process.version);
      expect(result.available).toBe(true);
    });
  });

  describe('checkServerSoftware', () => {
    it('should detect nginx', () => {
      mockExecSync.mockReturnValueOnce('nginx version: nginx/1.24.0');

      const result = checkServerSoftware();

      expect(result.name).toBe('Server');
      expect(result.available).toBe(true);
      expect(result.version).toBe('1.24.0');
      expect(result.details).toBe('nginx 1.24.0');
    });

    it('should detect apache via apache2 -v', () => {
      mockExecSync.mockImplementationOnce(() => {
        throw new Error('not found');
      });
      mockExecSync.mockReturnValueOnce(
        'Server version: Apache/2.4.57 (Unix)\nServer built:   Jul 15 2023 10:00:00'
      );

      const result = checkServerSoftware();

      expect(result.name).toBe('Server');
      expect(result.available).toBe(true);
      expect(result.version).toBe('2.4.57');
      expect(result.details).toBe('Apache 2.4.57');
    });

    it('should detect apache via httpd -v', () => {
      mockExecSync.mockImplementationOnce(() => {
        throw new Error('not found');
      });
      mockExecSync.mockReturnValueOnce(
        'Server version: Apache/2.4.52 (Debian)\n'
      );

      const result = checkServerSoftware();

      expect(result.available).toBe(true);
      expect(result.details).toBe('Apache 2.4.52');
    });

    it('should detect php-fpm when no web server is found', () => {
      mockExecSync.mockImplementation(((cmd: string) => {
        if (cmd.includes('nginx')) throw new Error('not found');
        if (cmd.includes('apache2')) throw new Error('not found');
        if (cmd.includes('httpd')) throw new Error('not found');
        if (cmd.includes('php-fpm')) {
          return 'PHP 8.1.12 (fpm-fcgi) (built: Oct 25 2022 00:00:00)\n' as any;
        }
        throw new Error('unexpected command');
      }) as any);

      const result = checkServerSoftware();

      expect(result.available).toBe(true);
      expect(result.version).toBe('8.1.12');
      expect(result.details).toBe('PHP-FPM 8.1.12');
    });

    it('should return not available when no server software detected', () => {
      mockExecSync.mockImplementation(() => {
        throw new Error('not found');
      });

      const result = checkServerSoftware();

      expect(result.name).toBe('Server');
      expect(result.available).toBe(false);
      expect(result.version).toBeNull();
    });

    it('should handle nginx output without version', () => {
      mockExecSync.mockReturnValueOnce('nginx');

      const result = checkServerSoftware();

      expect(result.available).toBe(true);
      expect(result.version).toBeNull();
      expect(result.details).toBe('nginx');
    });
  });

  describe('checkEnv', () => {
    it('should return allAvailable true when all components are present', () => {
      mockExecSync.mockReturnValueOnce(
        'PHP 8.2.10 (cli) (built: Aug 30 2023)\n'
      );
      mockExecSync.mockReturnValueOnce('nginx version: nginx/1.24.0');

      const result = checkEnv();

      expect(result.php.available).toBe(true);
      expect(result.node.available).toBe(true);
      expect(result.server.available).toBe(true);
      expect(result.allAvailable).toBe(true);
    });

    it('should return allAvailable false when PHP is missing', () => {
      mockExecSync.mockImplementationOnce(() => {
        throw new Error('not found');
      });
      mockExecSync.mockImplementationOnce(() => {
        throw new Error('not found');
      });
      mockExecSync.mockImplementationOnce(() => {
        throw new Error('not found');
      });
      mockExecSync.mockImplementationOnce(() => {
        throw new Error('not found');
      });

      const result = checkEnv();

      expect(result.php.available).toBe(false);
      expect(result.node.available).toBe(true);
      expect(result.server.available).toBe(false);
      expect(result.allAvailable).toBe(false);
    });
  });

  describe('registerEnvCheckCommand', () => {
    it('should register env:check command on program', () => {
      const program = createProgram();
      registerEnvCheckCommand(program, createTestCliOptions());

      const cmd = program.commands.find((c) => c.name() === 'env:check');
      expect(cmd).toBeDefined();
      expect(cmd!.description()).toContain('Check server environment');
    });

    it('should output JSON when --json flag is used', async () => {
      mockExecSync.mockReturnValueOnce('PHP 8.2.10 (cli)\n');
      mockExecSync.mockReturnValueOnce('nginx version: nginx/1.24.0');

      const program = createProgram();
      registerEnvCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync(['node', 'test', 'env:check', '--json']);
      } catch {
        // exitOverride may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      const result = JSON.parse(output);

      expect(result).toHaveProperty('php');
      expect(result).toHaveProperty('node');
      expect(result).toHaveProperty('server');
      expect(result).toHaveProperty('allAvailable');
      expect(result.php.version).toBe('8.2.10');
      expect(result.server.version).toBe('1.24.0');
      mockExit.mockRestore();
    });

    it('should output human-readable format without --json', async () => {
      mockExecSync.mockReturnValueOnce('PHP 8.2.10 (cli)\n');
      mockExecSync.mockImplementationOnce(() => {
        throw new Error('not found');
      });
      mockExecSync.mockImplementationOnce(() => {
        throw new Error('not found');
      });
      mockExecSync.mockImplementationOnce(() => {
        throw new Error('not found');
      });

      const program = createProgram();
      registerEnvCheckCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync(['node', 'test', 'env:check']);
      } catch {
        // exitOverride may throw
      }

      const allOutput = consoleSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('Server Environment');
      expect(allOutput).toContain('PHP');
      expect(allOutput).toContain('Node.js');
      mockExit.mockRestore();
    });

    it('should exit 0 when all components available', async () => {
      mockExecSync.mockReturnValueOnce('PHP 8.2.10 (cli)\n');
      mockExecSync.mockReturnValueOnce('nginx version: nginx/1.24.0');

      const program = createProgram();
      registerEnvCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync(['node', 'test', 'env:check', '--json']);
      } catch {
        // exitOverride may throw
      }

      expect(mockExit).toHaveBeenCalledWith(0);
      mockExit.mockRestore();
    });

    it('should exit 1 when not all components available', async () => {
      mockExecSync.mockImplementationOnce(() => {
        throw new Error('not found');
      });
      mockExecSync.mockImplementationOnce(() => {
        throw new Error('not found');
      });
      mockExecSync.mockImplementationOnce(() => {
        throw new Error('not found');
      });
      mockExecSync.mockImplementationOnce(() => {
        throw new Error('not found');
      });

      const program = createProgram();
      registerEnvCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync(['node', 'test', 'env:check', '--json']);
      } catch {
        // exitOverride may throw
      }

      expect(mockExit).toHaveBeenCalledWith(1);
      mockExit.mockRestore();
    });

    it('should show Not available in human-readable output when PHP is missing', async () => {
      mockExecSync.mockImplementationOnce(() => {
        throw new Error('not found');
      });
      mockExecSync.mockImplementationOnce(() => {
        throw new Error('not found');
      });
      mockExecSync.mockImplementationOnce(() => {
        throw new Error('not found');
      });
      mockExecSync.mockImplementationOnce(() => {
        throw new Error('not found');
      });

      const program = createProgram();
      registerEnvCheckCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync(['node', 'test', 'env:check']);
      } catch {
        // exitOverride may throw
      }

      const allOutput = consoleSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('Not available');
      expect(allOutput).toContain('Not detected');
      mockExit.mockRestore();
    });

    it('should produce valid JSON for all error cases', async () => {
      mockExecSync.mockImplementationOnce(() => {
        throw new Error('not found');
      });
      mockExecSync.mockImplementationOnce(() => {
        throw new Error('not found');
      });
      mockExecSync.mockImplementationOnce(() => {
        throw new Error('not found');
      });
      mockExecSync.mockImplementationOnce(() => {
        throw new Error('not found');
      });

      const program = createProgram();
      registerEnvCheckCommand(program, createTestCliOptions({ json: true }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync(['node', 'test', 'env:check', '--json']);
      } catch {
        // exitOverride may throw
      }

      const output = consoleSpy.mock.calls.map((c: any) => c[0]).join('');
      expect(() => JSON.parse(output)).not.toThrow();

      const result = JSON.parse(output);
      expect(result.php.available).toBe(false);
      expect(result.php.version).toBeNull();
      expect(result.server.available).toBe(false);
      expect(result.allAvailable).toBe(false);
      mockExit.mockRestore();
    });

    it('should show server details when a web server is detected', async () => {
      mockExecSync.mockReturnValueOnce('PHP 8.2.10 (cli)\n');
      mockExecSync.mockReturnValueOnce('nginx version: nginx/1.24.0');

      const program = createProgram();
      registerEnvCheckCommand(program, createTestCliOptions({ json: false }));

      const mockExit = jest.spyOn(process, 'exit').mockImplementation((() => {}) as any);

      try {
        await program.parseAsync(['node', 'test', 'env:check']);
      } catch {
        // exitOverride may throw
      }

      const allOutput = consoleSpy.mock.calls.map((c: any) => String(c[0])).join('\n');
      expect(allOutput).toContain('nginx 1.24.0');
      mockExit.mockRestore();
    });
  });
});
