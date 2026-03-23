import { Command } from 'commander';
import { execSync } from 'child_process';

interface EnvComponent {
  name: string;
  version: string | null;
  available: boolean;
  details?: string;
}

interface EnvCheckResult {
  php: EnvComponent;
  node: EnvComponent;
  server: EnvComponent;
  allAvailable: boolean;
}

function runCommand(cmd: string): string | null {
  try {
    const output = execSync(cmd, { encoding: 'utf-8', timeout: 5000 }).trim();
    return output || null;
  } catch {
    return null;
  }
}

export function checkPhpVersion(): EnvComponent {
  const versionOutput = runCommand('php -v');
  if (!versionOutput) {
    return { name: 'PHP', version: null, available: false };
  }

  const match = versionOutput.match(/PHP\s+(\d+\.\d+\.\d+)/);
  const version = match ? match[1] : null;
  const details = versionOutput.split('\n')[0] || undefined;

  return { name: 'PHP', version, available: !!version, details };
}

export function checkNodeVersion(): EnvComponent {
  const version = process.version;
  return {
    name: 'Node.js',
    version: version || null,
    available: !!version,
  };
}

export function checkServerSoftware(): EnvComponent {
  const nginxOutput = runCommand('nginx -v 2>&1');
  if (nginxOutput) {
    const match = nginxOutput.match(/nginx\/(\S+)/);
    return {
      name: 'Server',
      version: match ? match[1] : null,
      available: true,
      details: `nginx${match ? ' ' + match[1] : ''}`,
    };
  }

  const apacheOutput = runCommand('apache2 -v 2>&1') || runCommand('httpd -v 2>&1');
  if (apacheOutput) {
    const match = apacheOutput.match(/Apache\/(\S+)/) || apacheOutput.match(/Server version:\s*Apache\/(\S+)/);
    return {
      name: 'Server',
      version: match ? match[1] : null,
      available: true,
      details: `Apache${match ? ' ' + match[1] : ''}`,
    };
  }

  const phpFpmOutput = runCommand('php-fpm -v 2>&1');
  if (phpFpmOutput) {
    const match = phpFpmOutput.match(/PHP\s+(\d+\.\d+\.\d+)/);
    return {
      name: 'Server',
      version: match ? match[1] : null,
      available: true,
      details: `PHP-FPM${match ? ' ' + match[1] : ''}`,
    };
  }

  return { name: 'Server', version: null, available: false };
}

export function checkEnv(): EnvCheckResult {
  const php = checkPhpVersion();
  const node = checkNodeVersion();
  const server = checkServerSoftware();

  return {
    php,
    node,
    server,
    allAvailable: php.available && node.available && server.available,
  };
}

export function registerEnvCheckCommand(
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
    .command('env:check')
    .description('Check server environment components (PHP, Node.js, server software)')
    .option('--json', 'Output results as JSON', false)
    .action(async (cmdOptions) => {
      const opts = getOpts();
      const useJson = cmdOptions.json || opts.json;

      const result = checkEnv();

      if (useJson) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.log('Server Environment:');
        console.log(`  PHP: ${result.php.available ? result.php.version || 'Installed (version unknown)' : 'Not available'}`);
        console.log(`  Node.js: ${result.node.version || 'Not available'}`);
        if (result.server.available) {
          console.log(`  Server: ${result.server.details || 'Detected (version unknown)'}`);
        } else {
          console.log('  Server: Not detected');
        }
      }

      process.exit(result.allAvailable ? 0 : 1);
    });
}
