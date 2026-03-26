import chalk from 'chalk';

export function severityColor(severity: string): chalk.Chalk {
  switch (severity.toLowerCase()) {
    case 'critical': return chalk.red.bold;
    case 'high': return chalk.red;
    case 'medium': return chalk.yellow;
    case 'low': return chalk.green;
    case 'info': return chalk.blue;
    default: return chalk.gray;
  }
}

export function severityIcon(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical': return '🔴';
    case 'high': return '🟠';
    case 'medium': return '🟡';
    case 'low': return '🟢';
    case 'info': return '🔵';
    default: return '⚪';
  }
}
