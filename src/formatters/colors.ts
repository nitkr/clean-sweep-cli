import chalk from 'chalk';

export const colors = {
  critical: (text: string) => chalk.red.bold(text),
  high: (text: string) => chalk.yellow(text),
  medium: (text: string) => chalk.cyan(text),
  low: (text: string) => chalk.green(text),
  info: (text: string) => chalk.blue(text),
};

type ChalkFunction = (text: string) => string;

export function severityColor(severity: string): ChalkFunction {
  switch (severity.toLowerCase()) {
    case 'critical':
      return chalk.red.bold;
    case 'high':
      return chalk.yellow;
    case 'medium':
      return chalk.cyan;
    case 'low':
      return chalk.green;
    case 'info':
      return chalk.blue;
    default:
      return (text: string) => text;
  }
}

export function bold(text: string): string {
  return chalk.bold(text);
}
